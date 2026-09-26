package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/isaiahfoster/r2notary/cli/internal/entry"
	"github.com/isaiahfoster/r2notary/cli/internal/monitor"
	"github.com/isaiahfoster/r2notary/cli/internal/verify"
	"github.com/isaiahfoster/r2notary/cli/internal/verr"
)

// keygen: a note signer key and its verifier key, in golang.org/x/mod/sumdb/note format, which
// the TypeScript writer also reads (DECISIONS D1.4).
func cmdKeygen(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	name := fs.String("name", "", "key name: the log's origin (LOG_ORIGIN)")
	out := fs.String("out", "", "write the signer key here (created mode 0600, never overwritten)")
	if c := parse(fs, args, stderr); c >= 0 {
		return c
	}
	if *name == "" {
		return exitFor(stderr, usageErr("--name is required"))
	}
	skey, vkey, err := note.GenerateKey(rand.Reader, *name)
	if err != nil {
		return exitFor(stderr, err)
	}
	// GenerateKey does not check the name; loading the keys does (no spaces, no '+').
	if _, err := note.NewVerifier(vkey); err != nil {
		return exitFor(stderr, usageErr("--name %q is not a valid key name", *name))
	}
	if _, err := note.NewSigner(skey); err != nil {
		return exitFor(stderr, usageErr("--name %q is not a valid key name", *name))
	}
	if *out == "" {
		fmt.Fprintln(stdout, skey)
		fmt.Fprintln(stderr, "vkey:", vkey)
		return exitOK
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return exitFor(stderr, err)
	}
	if _, err := fmt.Fprintln(f, skey); err != nil {
		f.Close()
		return exitFor(stderr, err)
	}
	if err := f.Close(); err != nil {
		return exitFor(stderr, err)
	}
	fmt.Fprintln(stdout, vkey)
	return exitOK
}

func cmdCheckpoint(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("checkpoint", flag.ContinueOnError)
	var lf logFlags
	lf.register(fs)
	out := fs.String("out", "", "save the verified checkpoint to this file (for consistency --old)")
	if c := parse(fs, args, stderr); c >= 0 {
		return c
	}
	l, err := lf.open()
	if err != nil {
		return exitFor(stderr, err)
	}
	cp, err := l.Checkpoint(ctx)
	if err != nil {
		return exitFor(stderr, err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, cp.Note, 0o644); err != nil {
			return exitFor(stderr, err)
		}
	}
	// Checkpoints carry no time: the format has none, and R2Notary adds no extension lines.
	fmt.Fprintf(stdout, "origin %s\nsize %d\nroot %s\n", cp.Origin, cp.Tree.N,
		base64.StdEncoding.EncodeToString(cp.Tree.Hash[:]))
	fmt.Fprintf(stderr, "verified: signature by %s, origin %s\n", l.Verifier.Name(), cp.Origin)
	return exitOK
}

func cmdInclusion(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inclusion", flag.ContinueOnError)
	var lf logFlags
	lf.register(fs)
	index := fs.Int64("index", -1, "verify the entry at this index")
	key := fs.String("key", "", "verify every entry naming this object key")
	api := fs.String("api", "", "with --key: ask this deployment's lookup API (https://host) where the key's entries are, instead of scanning the whole log")
	if c := parse(fs, args, stderr); c >= 0 {
		return c
	}
	keySet := false
	fs.Visit(func(f *flag.Flag) { keySet = keySet || f.Name == "key" })
	if (*index >= 0) == keySet || (*api != "" && !keySet) {
		return exitFor(stderr, usageErr("pass exactly one of --index N (N >= 0) and --key K; --api needs --key"))
	}
	l, err := lf.open()
	if err != nil {
		return exitFor(stderr, err)
	}

	if !keySet {
		cp, err := l.Checkpoint(ctx)
		if err != nil {
			return exitFor(stderr, err)
		}
		inc, err := l.Inclusion(ctx, cp, *index)
		if err != nil {
			return exitFor(stderr, err)
		}
		fmt.Fprintf(stdout, "%s\n", entry.Line(inc.Index, inc.Entry))
		fmt.Fprintf(stderr, "verified: entry %d is in the tree of size %d (inclusion proof: %d hashes)\n",
			inc.Index, cp.Tree.N, inc.ProofHashes)
		return exitOK
	}

	var found int
	if *api == "" {
		found, err = keyByScan(ctx, l, *key, stdout, stderr)
	} else {
		found, err = keyByLookup(ctx, l, *api, *key, stdout, stderr)
	}
	if err != nil {
		return exitFor(stderr, err)
	}
	if found == 0 {
		fmt.Fprintf(stderr, "no entries for key %q\n", *key)
		return exitNegative
	}
	return exitOK
}

// keyByScan verifies every entry of the log and reports those naming key. Nothing is trusted, and
// nothing can be hidden, but it reads the whole log.
func keyByScan(ctx context.Context, l *verify.Log, key string, stdout, stderr io.Writer) (int, error) {
	cp, err := l.Checkpoint(ctx)
	if err != nil {
		return 0, err
	}
	found := 0
	err = l.Entries(ctx, cp, 0, cp.Tree.N, func(i int64, e []byte) error {
		if info := entry.Parse(e); info.HasKey && info.Key == key {
			found++
			fmt.Fprintf(stdout, "%s\n", entry.Line(i, e))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(stderr, "verified: all %d entries of the tree of size %d; %d name the key\n", cp.Tree.N, cp.Tree.N, found)
	return found, nil
}

// lookupPage is the part of /api/v1/lookup's answer the CLI uses. Only the indexes: the entries
// themselves are read from the log and proven.
type lookupPage struct {
	Entries []struct {
		Index int64 `json:"index"`
	} `json:"entries"`
	Next *int64 `json:"next"`
}

// maxLookupPage bounds one lookup response: at most 100 entries of at most 64 KiB, as JSON.
const maxLookupPage = 16 << 20

// keyByLookup asks the deployment's lookup API which indexes name key, then proves each one. The
// API is an unverified index: it cannot make the CLI accept a false entry, but it can leave
// entries out, which only a scan would notice.
func keyByLookup(ctx context.Context, l *verify.Log, api, key string, stdout, stderr io.Writer) (int, error) {
	base, err := url.Parse(api)
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
		return 0, usageErr("--api %q must be an absolute http(s) URL", api)
	}
	var indexes []int64
	after := int64(-1)
	for {
		u := base.JoinPath("api", "v1", "lookup")
		q := url.Values{"key": {key}}
		if after >= 0 {
			q.Set("after", strconv.FormatInt(after, 10))
		}
		u.RawQuery = q.Encode()
		body, err := l.Client.GetURL(ctx, u.String(), maxLookupPage)
		if err != nil {
			return 0, err
		}
		var page lookupPage
		if err := json.Unmarshal(body, &page); err != nil {
			return 0, fmt.Errorf("lookup API: %v", err)
		}
		for _, e := range page.Entries {
			indexes = append(indexes, e.Index)
		}
		if page.Next == nil {
			break
		}
		if *page.Next <= after {
			return 0, fmt.Errorf("lookup API: cursor did not advance (%d after %d)", *page.Next, after)
		}
		after = *page.Next
	}

	// Fetched after the lookup, so it covers every index the lookup saw (sizes only grow).
	cp, err := l.Checkpoint(ctx)
	if err != nil {
		return 0, err
	}
	for _, i := range indexes {
		inc, err := l.Inclusion(ctx, cp, i)
		var ie *verify.IndexError
		if errors.As(err, &ie) {
			return 0, verr.Failf("lookup API returned index %d, beyond the checkpoint's size %d", i, cp.Tree.N)
		}
		if err != nil {
			return 0, err
		}
		if info := entry.Parse(inc.Entry); !info.HasKey || info.Key != key {
			return 0, verr.Failf("lookup API returned index %d, whose entry does not name the key", i)
		}
		fmt.Fprintf(stdout, "%s\n", entry.Line(i, inc.Entry))
	}
	fmt.Fprintf(stderr, "verified: %d entries from the lookup API are in the tree of size %d (the API could still omit entries; omit --api to scan)\n",
		len(indexes), cp.Tree.N)
	return len(indexes), nil
}

func readCheckpointFile(l *verify.Log, path string) (*verify.Checkpoint, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cp, err := verify.OpenCheckpoint(b, l.Verifier, l.Origin)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cp, nil
}

func cmdConsistency(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("consistency", flag.ContinueOnError)
	var lf logFlags
	lf.register(fs)
	oldPath := fs.String("old", "", "a saved checkpoint (checkpoint --out, or an archived x-checkpoints/<size>)")
	newPath := fs.String("new", "", "prove against this saved checkpoint instead of the live one")
	if c := parse(fs, args, stderr); c >= 0 {
		return c
	}
	if *oldPath == "" {
		return exitFor(stderr, usageErr("--old is required"))
	}
	l, err := lf.open()
	if err != nil {
		return exitFor(stderr, err)
	}
	older, err := readCheckpointFile(l, *oldPath)
	if err != nil {
		return exitFor(stderr, err)
	}
	var newer *verify.Checkpoint
	if *newPath != "" {
		newer, err = readCheckpointFile(l, *newPath)
	} else {
		newer, err = l.Checkpoint(ctx)
	}
	if err != nil {
		return exitFor(stderr, err)
	}
	if err := l.Consistency(ctx, older, newer); err != nil {
		return exitFor(stderr, err)
	}
	fmt.Fprintf(stdout, "consistent %d -> %d\n", older.Tree.N, newer.Tree.N)
	return exitOK
}

func cmdMonitor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("monitor", flag.ContinueOnError)
	var lf logFlags
	lf.register(fs)
	statePath := fs.String("state", "", "state file: the last verified checkpoint (created if missing; a new monitor verifies the log from entry 0)")
	watch := fs.String("watch", "", "alert on any delete or overwrite of a key with this prefix")
	interval := fs.Duration("interval", 10*time.Second, "time between polls")
	once := fs.Bool("once", false, "poll once and exit (exit 3 if a watch alert fired)")
	quiet := fs.Bool("q", false, "do not print entries, only alerts and status")
	if c := parse(fs, args, stderr); c >= 0 {
		return c
	}
	if *statePath == "" {
		return exitFor(stderr, usageErr("--state is required"))
	}
	if *interval <= 0 {
		return exitFor(stderr, usageErr("--interval must be positive"))
	}
	l, err := lf.open()
	if err != nil {
		return exitFor(stderr, err)
	}
	m := &monitor.Monitor{
		Log: l,
		OnAlert: func(a monitor.Alert) {
			b, _ := json.Marshal(a)
			fmt.Fprintf(stdout, "%s\n", b)
			fmt.Fprintf(stderr, "ALERT: %s of %q at index %d (%s)\n", a.Kind, a.Key, a.Index, a.Action)
		},
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "watch" {
			m.Watch = watch
		}
	})
	if !*quiet {
		m.OnEntry = func(i int64, e []byte) { fmt.Fprintf(stdout, "%s\n", entry.Line(i, e)) }
	}

	for {
		code, alerts := pollOnce(ctx, m, *statePath, stderr)
		switch {
		case code == exitFailure || code == exitUsage:
			return code
		case *once && code != exitOK:
			return code
		case *once && alerts > 0:
			return exitNegative
		case *once:
			return exitOK
		}
		// Other errors (network, HTTP) are reported and retried on the next poll.
		select {
		case <-ctx.Done():
			return exitOK
		case <-time.After(*interval):
		}
	}
}

// pollOnce runs one poll and saves the new state. It returns an exit code and the alert count.
func pollOnce(ctx context.Context, m *monitor.Monitor, statePath string, stderr io.Writer) (int, int) {
	prev, err := monitor.Load(statePath)
	if err != nil {
		return exitFor(stderr, err), 0
	}
	next, res, err := m.Poll(ctx, prev)
	if err != nil {
		code := exitFor(stderr, err)
		if code == exitFailure && res != nil && res.Old != nil && res.New != nil {
			// Two signed checkpoints that cannot both be honest: keep them as evidence.
			fmt.Fprintf(stderr, "last verified checkpoint:\n%s\nserved checkpoint:\n%s\n", res.Old.Note, res.New.Note)
		}
		return code, 0
	}
	if err := monitor.Save(statePath, next); err != nil {
		return exitFor(stderr, err), 0
	}
	from := int64(0)
	if res.Old != nil {
		from = res.Old.Tree.N
	}
	fmt.Fprintf(stderr, "verified: tree size %d, consistent with size %d; %d new entries, %d alerts\n",
		res.New.Tree.N, from, res.New.Tree.N-from, res.Alerts)
	return exitOK, res.Alerts
}
