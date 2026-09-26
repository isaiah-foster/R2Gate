package monitor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/isaiahfoster/r2notary/cli/internal/testlog"
	"github.com/isaiahfoster/r2notary/cli/internal/tilefetch"
	"github.com/isaiahfoster/r2notary/cli/internal/verify"
	"github.com/isaiahfoster/r2notary/cli/internal/verr"
)

const origin = "example.com/log/test"

type recorder struct {
	indexes []int64
	alerts  []Alert
}

func newMonitor(t *testing.T, l *testlog.Log, watch *string) (*Monitor, *recorder) {
	t.Helper()
	c, err := tilefetch.NewClient(l.Server(t, ""), "")
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	return &Monitor{
		Log:     &verify.Log{Client: c, Verifier: l.Verifier(t), Origin: origin},
		Watch:   watch,
		OnEntry: func(i int64, _ []byte) { rec.indexes = append(rec.indexes, i) },
		OnAlert: func(a Alert) { rec.alerts = append(rec.alerts, a) },
	}, rec
}

func TestPollTailsNewEntries(t *testing.T) {
	ctx := context.Background()
	l := testlog.New(t, origin)
	l.Append(t, testlog.Entries(0, 300)...)
	m, rec := newMonitor(t, l, nil)

	st, res, err := m.Poll(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Old != nil || res.New.Tree.N != 300 || len(rec.indexes) != 300 || rec.indexes[299] != 299 {
		t.Fatalf("first poll: %+v, %d entries", res, len(rec.indexes))
	}

	// Nothing new: no entries.
	rec.indexes = nil
	st, _, err = m.Poll(ctx, st)
	if err != nil || len(rec.indexes) != 0 {
		t.Fatalf("idle poll: %v, %d entries", err, len(rec.indexes))
	}

	l.Append(t, testlog.Entries(300, 10)...)
	st, res, err = m.Poll(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if res.Old.Tree.N != 300 || res.New.Tree.N != 310 || len(rec.indexes) != 10 || rec.indexes[0] != 300 {
		t.Fatalf("second poll: old %d new %d, indexes %v", res.Old.Tree.N, res.New.Tree.N, rec.indexes)
	}
	cp, err := verify.OpenCheckpoint([]byte(st.Checkpoint), m.Log.Verifier, origin)
	if err != nil || cp.Tree.N != 310 {
		t.Fatalf("saved state: %v", err)
	}
}

func TestPollDetectsRollback(t *testing.T) {
	ctx := context.Background()
	l := testlog.New(t, origin)
	old := l.Append(t, testlog.Entries(0, 5)...)
	l.Append(t, testlog.Entries(5, 5)...)
	m, _ := newMonitor(t, l, nil)
	st, _, err := m.Poll(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.SetFile("checkpoint", old) // serve the size-5 checkpoint again
	_, res, err := m.Poll(ctx, st)
	if !verr.IsFailure(err) || !strings.Contains(err.Error(), "backwards") {
		t.Fatalf("rollback: %v", err)
	}
	if res == nil || res.Old.Tree.N != 10 || res.New.Tree.N != 5 {
		t.Fatalf("evidence missing: %+v", res)
	}
}

// A log signed with the same key that has rewritten history: a split view or a rewrite after
// key compromise. The monitor holds the old checkpoint, so the new one cannot be proven to
// extend it.
func TestPollDetectsFork(t *testing.T) {
	ctx := context.Background()
	l := testlog.New(t, origin)
	l.Append(t, testlog.Entries(0, 300)...)
	m, _ := newMonitor(t, l, nil)
	st, _, err := m.Poll(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	for name, build := range map[string]func(f *testlog.Log){
		"rewritten entry, larger tree": func(f *testlog.Log) {
			e := testlog.Entries(0, 400)
			e[17] = testlog.Entry("object.event", "obj/000017", "DeleteObject")
			f.Append(t, e...)
		},
		"same size, different root": func(f *testlog.Log) {
			e := testlog.Entries(0, 300)
			e[299] = testlog.Entry("object.event", "x", "PutObject")
			f.Append(t, e...)
		},
	} {
		f := testlog.NewWithKey(t, origin, l.SKey, l.VKey)
		build(f)
		fm, _ := newMonitor(t, f, nil)
		if _, _, err := fm.Poll(ctx, st); !verr.IsFailure(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPollRejectsCorruptStateWithoutBlamingTheLog(t *testing.T) {
	ctx := context.Background()
	l := testlog.New(t, origin)
	l.Append(t, testlog.Entries(0, 3)...)
	m, _ := newMonitor(t, l, nil)
	st, _, err := m.Poll(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Checkpoint = strings.Replace(st.Checkpoint, "\n3\n", "\n2\n", 1)
	if _, _, err := m.Poll(ctx, st); err == nil || verr.IsFailure(err) {
		t.Fatalf("tampered state: %v", err)
	}
}

func TestWatch(t *testing.T) {
	ctx := context.Background()
	l := testlog.New(t, origin)
	e := func(typ, key, action string) []byte { return testlog.Entry(typ, key, action) }
	l.Append(t,
		e("object.event", "locked/a", "PutObject"),         // 0: create
		e("object.event", "open/a", "PutObject"),           // 1: outside the prefix
		e("object.event", "open/a", "DeleteObject"),        // 2: outside the prefix
		e("object.snapshot", "locked/s", ""),               // 3: baseline, no alert
		e("object.event", "locked/a", "CopyObject"),        // 4: overwrite
		e("object.event", "locked/b", "DeleteObject"),      // 5: delete of a key never seen
		e("object.event", "locked/a", "LifecycleDeletion"), // 6: delete
		e("object.event", "locked/a", "PutObject"),         // 7: create again: not an overwrite
		e("object.event", "lockedX", "DeleteObject"),       // 8: shares the prefix string
		e("object.event", "locked/c", "DeleteObject")[:10], // 9: not JSON: no alert, no failure
		e("object.event", "locked/s", "PutObject"),         // 10: overwrites the snapshot
	)
	prefix := "locked/"
	m, rec := newMonitor(t, l, &prefix)
	st, res, err := m.Poll(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Alert{
		{Index: 4, Kind: "overwrite", Key: "locked/a", Action: "CopyObject"},
		{Index: 5, Kind: "delete", Key: "locked/b", Action: "DeleteObject"},
		{Index: 6, Kind: "delete", Key: "locked/a", Action: "LifecycleDeletion"},
		{Index: 10, Kind: "overwrite", Key: "locked/s", Action: "PutObject"},
	}
	if len(rec.alerts) != len(want) || res.Alerts != len(want) {
		t.Fatalf("alerts %+v", rec.alerts)
	}
	for i := range want {
		if rec.alerts[i] != want[i] {
			t.Errorf("alert %d = %+v, want %+v", i, rec.alerts[i], want[i])
		}
	}
	if got := strings.Join(st.Watch.Live, ","); got != "locked/a,locked/s" {
		t.Errorf("live = %s", got)
	}

	// The live set persists: an overwrite in a later poll is caught.
	rec.alerts = nil
	l.Append(t, e("object.event", "locked/a", "CompleteMultipartUpload"))
	if _, _, err := m.Poll(ctx, st); err != nil || len(rec.alerts) != 1 || rec.alerts[0].Index != 11 {
		t.Fatalf("later overwrite: %v %+v", err, rec.alerts)
	}

	// The watch must match the state it was built with.
	other := "other/"
	m.Watch = &other
	if _, _, err := m.Poll(ctx, st); err == nil || verr.IsFailure(err) {
		t.Errorf("prefix changed: %v", err)
	}
	m.Watch = nil
	if _, _, err := m.Poll(ctx, st); err == nil {
		t.Errorf("watch dropped: accepted")
	}
	plain, _ := newMonitor(t, l, nil)
	unwatched, _, err := plain.Poll(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Watch = &prefix
	if _, _, err := m.Poll(ctx, unwatched); err == nil {
		t.Errorf("watch added to a state that did not track it: accepted")
	}
}

func TestStateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	st, err := Load(path)
	if err != nil || st != nil {
		t.Fatalf("missing file: %v %v", st, err)
	}
	want := &State{Checkpoint: "c\n", Watch: &WatchState{Prefix: "p/", Live: []string{"p/a"}}}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got.Checkpoint != want.Checkpoint || got.Watch.Prefix != "p/" || len(got.Watch.Live) != 1 {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("corrupt state accepted")
	}
}
