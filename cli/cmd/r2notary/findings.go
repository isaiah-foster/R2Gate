package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strconv"

	"github.com/isaiahfoster/r2notary/cli/internal/entry"
	"github.com/isaiahfoster/r2notary/cli/internal/verify"
	"github.com/isaiahfoster/r2notary/cli/internal/verr"
)

// findingsPage is the part of /api/v1/findings the CLI uses. As with lookup, only indexes are
// taken from the API; the entries are read from the log and proven.
type findingsPage struct {
	Scan *struct {
		ScanID     string `json:"scanId"`
		State      string `json:"state"`
		StartIndex *int64 `json:"startIndex"`
		EndIndex   *int64 `json:"endIndex"`
	} `json:"scan"`
	Findings []struct {
		Index int64 `json:"index"`
	} `json:"findings"`
	Next *int64 `json:"next"`
}

// maxFindingsPage bounds one findings response: at most 1,000 entries of at most 64 KiB, as JSON.
const maxFindingsPage = 80 << 20

func cmdFindings(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	var lf logFlags
	lf.register(fs)
	api := fs.String("api", "", "the deployment whose /api/v1/findings lists the latest audit (https://host)")
	if c := parse(fs, args, stderr); c >= 0 {
		return c
	}
	base, err := url.Parse(*api)
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
		return exitFor(stderr, usageErr("--api %q must be an absolute http(s) URL", *api))
	}
	l, err := lf.open()
	if err != nil {
		return exitFor(stderr, err)
	}
	n, err := verifyFindings(ctx, l, base, stdout, stderr)
	if err != nil {
		return exitFor(stderr, err)
	}
	if n < 0 {
		fmt.Fprintln(stderr, "no audit has run")
		return exitNegative
	}
	return exitOK
}

// verifyFindings lists the latest audit's findings from the API, proves that each one is an
// audit.finding of that scan in the signed log, and, once the scan's audit.scan end entry is in
// the log, checks the number of findings against the count that entry commits to. The API can
// therefore not add a finding or hide one from a finished scan. It returns the number of findings
// proven, or -1 if no audit has run.
func verifyFindings(ctx context.Context, l *verify.Log, base *url.URL, stdout, stderr io.Writer) (int, error) {
	var scanID, state string
	var start, end *int64
	var indexes []int64
	after := int64(-1)
	for page := 0; ; page++ {
		u := base.JoinPath("api", "v1", "findings")
		if after >= 0 {
			u.RawQuery = url.Values{"after": {strconv.FormatInt(after, 10)}}.Encode()
		}
		body, err := l.Client.GetURL(ctx, u.String(), maxFindingsPage)
		if err != nil {
			return 0, err
		}
		var p findingsPage
		if err := json.Unmarshal(body, &p); err != nil {
			return 0, fmt.Errorf("findings API: %v", err)
		}
		if p.Scan == nil {
			return -1, nil
		}
		if page == 0 {
			scanID, state, start, end = p.Scan.ScanID, p.Scan.State, p.Scan.StartIndex, p.Scan.EndIndex
		} else if p.Scan.ScanID != scanID {
			return 0, fmt.Errorf("findings API: the latest scan changed while paging; run again")
		}
		for _, f := range p.Findings {
			indexes = append(indexes, f.Index)
		}
		if p.Next == nil {
			break
		}
		if *p.Next <= after {
			return 0, fmt.Errorf("findings API: cursor did not advance (%d after %d)", *p.Next, after)
		}
		after = *p.Next
	}

	// Fetched after the API, so it covers every published index the API saw (sizes only grow).
	cp, err := l.Checkpoint(ctx)
	if err != nil {
		return 0, err
	}
	prove := func(i int64, what string, ok func(entry.Info) bool) ([]byte, error) {
		inc, err := l.Inclusion(ctx, cp, i)
		if err != nil {
			return nil, err
		}
		if !ok(entry.Parse(inc.Entry)) {
			return nil, verr.Failf("findings API: entry %d is not %s", i, what)
		}
		return inc.Entry, nil
	}
	if start != nil && *start < cp.Tree.N {
		if _, err := prove(*start, "the start of scan "+scanID, func(e entry.Info) bool { return e.IsScan(scanID, "start") }); err != nil {
			return 0, err
		}
	}
	proven, pending := 0, 0
	for _, i := range indexes {
		if i >= cp.Tree.N {
			pending++ // durable but not yet covered by a checkpoint
			continue
		}
		e, err := prove(i, "a finding of scan "+scanID, func(e entry.Info) bool { return e.IsFinding(scanID) })
		if err != nil {
			return 0, err
		}
		proven++
		fmt.Fprintf(stdout, "%s\n", entry.Line(i, e))
	}

	summary := fmt.Sprintf("verified: %d findings of scan %s (%s) are in the tree of size %d", proven, scanID, state, cp.Tree.N)
	if pending > 0 {
		summary += fmt.Sprintf("; %d more are not yet covered by a checkpoint", pending)
	}
	if end != nil && *end < cp.Tree.N {
		e, err := prove(*end, "the end of scan "+scanID, func(e entry.Info) bool { return e.IsScan(scanID, "end") && e.HasFindings })
		if err != nil {
			return 0, err
		}
		signed := entry.Parse(e).Findings
		if signed != int64(len(indexes)) {
			return 0, verr.Failf("findings API listed %d findings; scan %s's signed end entry (index %d) says %d", len(indexes), scanID, *end, signed)
		}
		summary += fmt.Sprintf("; the signed end entry (index %d) confirms the count", *end)
	} else {
		summary += "; the scan has not ended in this checkpoint, so the API could still omit findings"
	}
	fmt.Fprintln(stderr, summary)
	return proven, nil
}
