package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/isaiahfoster/r2notary/cli/internal/testlog"
)

// auditFixture is a log of 20 object events, then scan "s1": start (20), findings (21, 22), an
// unrelated event (23), end (24, committing to 2 findings).
func auditFixture(t *testing.T) []string {
	t.Helper()
	l := testlog.New(t, origin)
	l.Append(t, testlog.Entries(0, 20)...)
	finding := func(key string) []byte {
		return fmt.Appendf(nil, `{"key":%q,"kind":"MISSING_OBJECT","scanId":"s1","type":"audit.finding","v":1}`, key)
	}
	l.Append(t,
		[]byte(`{"logSizeAtStart":20,"phase":"start","scanId":"s1","type":"audit.scan","v":1}`),
		finding("a"),
		finding("b"),
		testlog.Entry("object.event", "c", "PutObject"),
		[]byte(`{"findings":2,"objectsScanned":9,"phase":"end","scanId":"s1","type":"audit.scan","v":1}`),
	)
	return []string{"--log", l.Server(t, ""), "--vkey", l.VKey}
}

// findingsServer answers /api/v1/findings with one finding per page, in R2Notary's shape.
func findingsServer(t *testing.T, scan string, indexes []int64) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/findings" {
			http.NotFound(w, r)
			return
		}
		if scan == "" {
			fmt.Fprint(w, `{"scan":null,"size":0,"findings":[],"next":null}`)
			return
		}
		i := 0
		if a := r.URL.Query().Get("after"); a != "" {
			for i < len(indexes) && fmt.Sprint(indexes[i]) != a {
				i++
			}
			i++
		}
		var page []string
		next := "null"
		if i < len(indexes) {
			page = append(page, fmt.Sprintf(`{"index":%d,"published":true,"entry":{}}`, indexes[i]))
			if i < len(indexes)-1 {
				next = fmt.Sprint(indexes[i])
			}
		}
		fmt.Fprintf(w, `{"scan":%s,"size":25,"findings":[%s],"next":%s}`, scan, strings.Join(page, ","), next)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

const doneScan = `{"scanId":"s1","state":"done","startIndex":20,"endIndex":24}`

func TestFindingsVerified(t *testing.T) {
	flags := auditFixture(t)
	api := findingsServer(t, doneScan, []int64{21, 22})
	code, out, errb := runCLI(t, append([]string{"findings", "--api", api}, flags...)...)
	if code != exitOK || strings.Count(out, "\n") != 2 || !strings.HasPrefix(out, `{"index":21,`) ||
		!strings.Contains(errb, "confirms the count") {
		t.Fatalf("exit %d, %q, %q", code, out, errb)
	}
}

func TestFindingsLyingAPI(t *testing.T) {
	flags := auditFixture(t)
	for name, c := range map[string]struct {
		scan    string
		indexes []int64
	}{
		"omits a finding":           {doneScan, []int64{21}},
		"adds a non-finding":        {doneScan, []int64{21, 22, 23}},
		"cites another scan":        {strings.Replace(doneScan, `"s1"`, `"s2"`, 1), []int64{21, 22}},
		"misplaces the start entry": {strings.Replace(doneScan, `"startIndex":20`, `"startIndex":21`, 1), []int64{21, 22}},
		"misplaces the end entry":   {strings.Replace(doneScan, `"endIndex":24`, `"endIndex":23`, 1), []int64{21, 22}},
	} {
		api := findingsServer(t, c.scan, c.indexes)
		if code, _, errb := runCLI(t, append([]string{"findings", "--api", api}, flags...)...); code != exitFailure {
			t.Errorf("%s: exit %d, %q", name, code, errb)
		}
	}
}

func TestFindingsUnfinishedAndAbsent(t *testing.T) {
	flags := auditFixture(t)
	// A scan still running: its end is not in the log yet, and one finding is not yet published.
	running := `{"scanId":"s1","state":"confirming","startIndex":20,"endIndex":null}`
	api := findingsServer(t, running, []int64{21, 22, 99})
	code, out, errb := runCLI(t, append([]string{"findings", "--api", api}, flags...)...)
	if code != exitOK || strings.Count(out, "\n") != 2 || !strings.Contains(errb, "1 more are not yet covered") ||
		!strings.Contains(errb, "could still omit") {
		t.Fatalf("running: exit %d, %q, %q", code, out, errb)
	}
	if code, _, _ := runCLI(t, append([]string{"findings", "--api", findingsServer(t, "", nil)}, flags...)...); code != exitNegative {
		t.Fatalf("no audit: exit %d", code)
	}
	if code, _, _ := runCLI(t, append([]string{"findings", "--api", "ftp://x"}, flags...)...); code != exitUsage {
		t.Fatalf("bad --api: exit %d", code)
	}
}
