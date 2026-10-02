// Package monitor follows a log over time (PLAN §5.7). Each poll verifies the live checkpoint,
// proves it consistent with the last checkpoint this monitor verified, then verifies and reports
// every new entry. A size regression, a fork, or any data that does not verify is a failure. The
// monitor's state is the last verified checkpoint (the signed note itself, so it can be shown to
// others as evidence) and, with --watch, the keys live under the protected prefix.
package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/isaiahfoster/r2notary/cli/internal/entry"
	"github.com/isaiahfoster/r2notary/cli/internal/verify"
)

// ErrWatchBlinded: the log blinds key names (keyHmac, M8), so no prefix can be matched. Failing is
// better than watching silently and never alerting.
var ErrWatchBlinded = errors.New("this log blinds key names (keyHmac): --watch cannot match a prefix")

// State is what a monitor persists between polls.
type State struct {
	// Checkpoint is the signed note of the last checkpoint whose entries were all verified.
	Checkpoint string      `json:"checkpoint"`
	Watch      *WatchState `json:"watch,omitempty"`
}

// WatchState tracks the keys under a protected prefix that the log currently shows as present.
type WatchState struct {
	Prefix string   `json:"prefix"`
	Live   []string `json:"live"`
}

// Alert reports a delete or overwrite under the watched prefix.
type Alert struct {
	Index  int64  `json:"index"`
	Kind   string `json:"alert"` // "delete" or "overwrite"
	Key    string `json:"key"`
	Action string `json:"action"`
}

// Monitor polls one log.
type Monitor struct {
	Log *verify.Log
	// Watch, if set, is a key prefix under which objects must never be deleted or replaced.
	Watch   *string
	OnEntry func(index int64, entry []byte)
	OnAlert func(Alert)
}

// Result describes a poll. On a verification failure it still carries both checkpoints, as
// evidence of the misbehaviour.
type Result struct {
	Old    *verify.Checkpoint // nil on the first poll
	New    *verify.Checkpoint
	Alerts int
}

// Poll performs one round. prev is nil for a new monitor, which then verifies the whole log from
// entry 0. The returned state is only valid if err is nil; the caller saves it.
func (m *Monitor) Poll(ctx context.Context, prev *State) (*State, *Result, error) {
	res := &Result{}
	var from int64
	live := map[string]bool{}
	if prev != nil {
		// The state file is local; a bad one is an operational error, not the log's fault.
		old, err := verify.OpenCheckpoint([]byte(prev.Checkpoint), m.Log.Verifier, m.Log.Origin)
		if err != nil {
			return nil, nil, fmt.Errorf("saved checkpoint in the state file does not verify: %v", err)
		}
		res.Old, from = old, old.Tree.N
	}
	if err := checkWatch(m.Watch, prev, from); err != nil {
		return nil, nil, err
	}
	if prev != nil && prev.Watch != nil {
		for _, k := range prev.Watch.Live {
			live[k] = true
		}
	}

	cp, err := m.Log.Checkpoint(ctx)
	if err != nil {
		return nil, nil, err
	}
	res.New = cp
	if res.Old != nil {
		if err := m.Log.Consistency(ctx, res.Old, cp); err != nil {
			return nil, res, err
		}
	}

	err = m.Log.Entries(ctx, cp, from, cp.Tree.N, func(i int64, e []byte) error {
		if m.OnEntry != nil {
			m.OnEntry(i, e)
		}
		if m.Watch == nil {
			return nil
		}
		info := entry.Parse(e)
		if info.HasKeyHmac {
			return ErrWatchBlinded
		}
		if !info.HasKey || !strings.HasPrefix(info.Key, *m.Watch) {
			return nil
		}
		alert := ""
		switch {
		case info.IsDelete():
			alert = "delete"
			delete(live, info.Key)
		case info.IsWrite():
			if live[info.Key] {
				alert = "overwrite"
			}
			live[info.Key] = true
		case info.IsSnapshot():
			live[info.Key] = true
		}
		if alert != "" {
			res.Alerts++
			if m.OnAlert != nil {
				m.OnAlert(Alert{Index: i, Kind: alert, Key: info.Key, Action: info.Action})
			}
		}
		return nil
	})
	if err != nil {
		return nil, res, err
	}

	next := &State{Checkpoint: string(cp.Note)}
	if m.Watch != nil {
		keys := make([]string, 0, len(live))
		for k := range live {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		next.Watch = &WatchState{Prefix: *m.Watch, Live: keys}
	}
	return next, res, nil
}

// checkWatch requires the watch to match the state: the live set is only meaningful if it was
// built from every entry since the start of the log with the same prefix.
func checkWatch(watch *string, prev *State, from int64) error {
	var had *WatchState
	if prev != nil {
		had = prev.Watch
	}
	switch {
	case watch == nil && had != nil:
		return fmt.Errorf("the state file watches %q; pass the same --watch", had.Prefix)
	case watch != nil && had != nil && *watch != had.Prefix:
		return fmt.Errorf("the state file watches %q, not %q; use a new state file to change it", had.Prefix, *watch)
	case watch != nil && had == nil && from > 0:
		return fmt.Errorf("the state file was created without --watch, so it does not know which keys exist; use a new state file")
	}
	return nil
}

// Load reads a state file. A missing file means a new monitor: (nil, nil).
func Load(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil || st.Checkpoint == "" {
		return nil, fmt.Errorf("state file %s is not a monitor state: %v", path, err)
	}
	return &st, nil
}

// Save writes a state file atomically: a temporary file in the same directory, synced, then
// renamed over the old one, so a crash leaves either the old or the new state.
func Save(path string, st *State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
