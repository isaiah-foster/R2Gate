package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/isaiahfoster/r2notary/cli/internal/testlog"
)

const origin = "example.com/log/test"

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRunVersion(t *testing.T) {
	code, out, errb := runCLI(t, "version")
	if code != exitOK || !strings.HasPrefix(out, "r2notary ") {
		t.Fatalf("exit %d, out %q, stderr %q", code, out, errb)
	}
}

func TestRunUsage(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"bogus"},
		{"checkpoint"}, // missing --log/--vkey
		{"checkpoint", "--log", "x", "--vkey", "y"}, // bad URL and vkey
		{"inclusion", "--log", "https://h/log/x", "--vkey", "v"},
		{"monitor", "--log", "https://h/log/x", "--vkey", "v"},
		{"keygen"},
		{"checkpoint", "--nope"},
		{"checkpoint", "extra"},
	} {
		if code, _, errb := runCLI(t, args...); code != exitUsage {
			t.Errorf("%v: exit %d, stderr %q", args, code, errb)
		}
	}
}

// fixture is a test log with 600 entries; entries 10 and 400 name the key "wanted".
func fixture(t *testing.T) (*testlog.Log, []string) {
	t.Helper()
	l := testlog.New(t, origin)
	entries := testlog.Entries(0, 600)
	entries[10] = testlog.Entry("object.event", "wanted", "PutObject")
	entries[400] = testlog.Entry("object.event", "wanted", "DeleteObject")
	l.Append(t, entries[:300]...)
	l.Append(t, entries[300:]...)
	return l, []string{"--log", l.Server(t, ""), "--vkey", l.VKey}
}

func TestCheckpointAndConsistency(t *testing.T) {
	l, flags := fixture(t)
	dir := t.TempDir()
	saved := filepath.Join(dir, "cp")
	code, out, errb := runCLI(t, append([]string{"checkpoint", "--out", saved}, flags...)...)
	if code != exitOK || !strings.Contains(out, "size 600\n") || !strings.Contains(out, "origin "+origin+"\n") {
		t.Fatalf("checkpoint: exit %d, %q, %q", code, out, errb)
	}
	old := filepath.Join(dir, "old")
	archived, _ := l.File("x-checkpoints/300")
	if err := os.WriteFile(old, archived, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errb := runCLI(t, append([]string{"consistency", "--old", old}, flags...)...); code != exitOK || out != "consistent 300 -> 600\n" {
		t.Fatalf("consistency: exit %d, %q, %q", code, out, errb)
	}
	if code, out, _ := runCLI(t, append([]string{"consistency", "--old", old, "--new", saved}, flags...)...); code != exitOK || out != "consistent 300 -> 600\n" {
		t.Fatalf("consistency --new: exit %d, %q", code, out)
	}
	// Reversed: the "old" one is newer. A rollback.
	if code, _, errb := runCLI(t, append([]string{"consistency", "--old", saved, "--new", old}, flags...)...); code != exitFailure {
		t.Fatalf("reversed: exit %d, %q", code, errb)
	}
	// A saved checkpoint signed by another key is rejected.
	other := testlog.New(t, origin)
	if err := os.WriteFile(old, other.Append(t, []byte("x")), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, append([]string{"consistency", "--old", old}, flags...)...); code != exitFailure {
		t.Fatalf("foreign checkpoint: exit %d", code)
	}
}

func TestInclusionByIndex(t *testing.T) {
	_, flags := fixture(t)
	code, out, errb := runCLI(t, append([]string{"inclusion", "--index", "10"}, flags...)...)
	var line struct {
		Index int64           `json:"index"`
		Entry json.RawMessage `json:"entry"`
	}
	if code != exitOK || json.Unmarshal([]byte(out), &line) != nil || line.Index != 10 || !strings.Contains(string(line.Entry), `"wanted"`) {
		t.Fatalf("exit %d, %q, %q", code, out, errb)
	}
	if code, _, _ := runCLI(t, append([]string{"inclusion", "--index", "600"}, flags...)...); code != exitNegative {
		t.Fatalf("index beyond the tree: exit %d", code)
	}
}

func TestInclusionByKeyScan(t *testing.T) {
	_, flags := fixture(t)
	code, out, errb := runCLI(t, append([]string{"inclusion", "--key", "wanted"}, flags...)...)
	if code != exitOK || strings.Count(out, "\n") != 2 || !strings.HasPrefix(out, `{"index":10,`) {
		t.Fatalf("exit %d, %q, %q", code, out, errb)
	}
	if code, _, _ := runCLI(t, append([]string{"inclusion", "--key", "absent"}, flags...)...); code != exitNegative {
		t.Fatalf("absent key: exit %d", code)
	}
}

// lookupServer serves /api/v1/lookup with the given pages of indexes, in R2Notary's shape.
func lookupServer(t *testing.T, pages [][]int64) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/lookup" || r.URL.Query().Get("key") != "wanted" {
			http.NotFound(w, r)
			return
		}
		page := 0
		if a := r.URL.Query().Get("after"); a != "" {
			after, _ := strconv.ParseInt(a, 10, 64)
			for page < len(pages) && pages[page][len(pages[page])-1] <= after {
				page++
			}
		}
		var entries []string
		for _, i := range pages[page] {
			entries = append(entries, fmt.Sprintf(`{"index":%d,"entry":{}}`, i))
		}
		next := "null"
		if page < len(pages)-1 {
			next = strconv.FormatInt(pages[page][len(pages[page])-1], 10)
		}
		fmt.Fprintf(w, `{"key":"wanted","size":600,"entries":[%s],"next":%s}`, strings.Join(entries, ","), next)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestInclusionByKeyLookup(t *testing.T) {
	_, flags := fixture(t)
	api := lookupServer(t, [][]int64{{10}, {400}})
	code, out, errb := runCLI(t, append([]string{"inclusion", "--key", "wanted", "--api", api}, flags...)...)
	if code != exitOK || strings.Count(out, "\n") != 2 || !strings.Contains(out, `{"index":400,`) {
		t.Fatalf("exit %d, %q, %q", code, out, errb)
	}
	// A lying API: an index whose entry is about another key, or beyond the tree.
	for _, bad := range [][][]int64{{{10, 11}}, {{10}, {700}}} {
		api := lookupServer(t, bad)
		if code, _, errb := runCLI(t, append([]string{"inclusion", "--key", "wanted", "--api", api}, flags...)...); code != exitFailure {
			t.Errorf("lookup %v: exit %d, %q", bad, code, errb)
		}
	}
}

func TestPrivateLogToken(t *testing.T) {
	l := testlog.New(t, origin)
	l.Append(t, testlog.Entries(0, 3)...)
	const token = "secret-read-token-secret-read-token"
	flags := []string{"--log", l.Server(t, token), "--vkey", l.VKey}
	if code, _, errb := runCLI(t, append([]string{"checkpoint"}, flags...)...); code != exitError || !strings.Contains(errb, "401") {
		t.Fatalf("no token: exit %d, %q", code, errb)
	}
	t.Setenv(tokenEnv, token)
	if code, _, errb := runCLI(t, append([]string{"inclusion", "--index", "2"}, flags...)...); code != exitOK {
		t.Fatalf("token from env: exit %d, %q", code, errb)
	}
	t.Setenv(tokenEnv, "")
	tf := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tf, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := runCLI(t, append([]string{"checkpoint", "--token-file", tf}, flags...)...); code != exitOK {
		t.Fatalf("token file: exit %d, %q", code, errb)
	}
}

func TestVKeyFromFile(t *testing.T) {
	l := testlog.New(t, origin)
	l.Append(t, []byte("x"))
	vf := filepath.Join(t.TempDir(), "vkey")
	if err := os.WriteFile(vf, []byte(l.VKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := runCLI(t, "checkpoint", "--log", l.Server(t, ""), "--vkey", "@"+vf); code != exitOK {
		t.Fatalf("exit %d, %q", code, errb)
	}
}

func TestCorruptionExitsWithFailure(t *testing.T) {
	l, flags := fixture(t)
	tile, _ := l.File("tile/0/001")
	tile[100] ^= 0x10
	l.SetFile("tile/0/001", tile)
	code, _, errb := runCLI(t, append([]string{"inclusion", "--index", "300"}, flags...)...)
	if code != exitFailure || !strings.Contains(errb, "verification failed") {
		t.Fatalf("exit %d, %q", code, errb)
	}
	l.SetFile("tile/entries/001", nil)
	if code, _, errb := runCLI(t, append([]string{"inclusion", "--index", "300"}, flags...)...); code != exitError {
		t.Fatalf("missing bundle: exit %d, %q", code, errb)
	}
}

func TestMonitorOnce(t *testing.T) {
	l, flags := fixture(t)
	state := filepath.Join(t.TempDir(), "state.json")
	args := append([]string{"monitor", "--once", "-q", "--state", state, "--watch", "want"}, flags...)
	code, out, errb := runCLI(t, args...)
	// Entry 400 deletes "wanted": one alert, exit 3.
	if code != exitNegative || !strings.Contains(out, `"alert":"delete"`) || !strings.Contains(errb, "tree size 600") {
		t.Fatalf("first poll: exit %d, %q, %q", code, out, errb)
	}
	code, out, _ = runCLI(t, args...)
	if code != exitOK || out != "" {
		t.Fatalf("idle poll: exit %d, %q", code, out)
	}

	l.Append(t, testlog.Entries(600, 5)...)
	noWatch := append([]string{"monitor", "--once", "--state", filepath.Join(t.TempDir(), "s")}, flags...)
	code, out, _ = runCLI(t, noWatch...)
	if code != exitOK || strings.Count(out, "\n") != 605 {
		t.Fatalf("fresh monitor prints every entry: exit %d, %d lines", code, strings.Count(out, "\n"))
	}

	// Rollback: serve the size-300 checkpoint. The evidence goes to stderr.
	old, _ := l.File("x-checkpoints/300")
	l.SetFile("checkpoint", old)
	code, _, errb = runCLI(t, args...)
	if code != exitFailure || !strings.Contains(errb, "last verified checkpoint:") {
		t.Fatalf("rollback: exit %d, %q", code, errb)
	}
	// The state still holds the last good checkpoint.
	b, _ := os.ReadFile(state)
	if !strings.Contains(string(b), `\n600\n`) {
		t.Fatalf("state overwritten after a failure: %s", b)
	}
}

func TestKeygen(t *testing.T) {
	out := filepath.Join(t.TempDir(), "skey")
	code, vkey, errb := runCLI(t, "keygen", "--name", origin, "--out", out)
	if code != exitOK || !strings.HasPrefix(vkey, origin+"+") {
		t.Fatalf("exit %d, %q, %q", code, vkey, errb)
	}
	st, err := os.Stat(out)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
	if code, _, _ := runCLI(t, "keygen", "--name", origin, "--out", out); code != exitError {
		t.Fatalf("overwrote an existing key: exit %d", code)
	}
	if code, _, _ := runCLI(t, "keygen", "--name", "bad name"); code != exitUsage {
		t.Fatalf("invalid name: exit %d", code)
	}
}
