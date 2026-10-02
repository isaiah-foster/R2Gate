// Package testlog builds tlog-tiles logs in memory for tests, using golang.org/x/mod/sumdb/tlog
// to compute the tree and tlog.Tile.Path() (rewritten to the tlog-tiles layout) to name tiles.
// It is a second, Go-only writer: the TypeScript writer is exercised by scripts/conformance.ts.
package testlog

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Log is an in-memory tlog-tiles log with a signing key, served by Server.
type Log struct {
	Origin string
	VKey   string
	SKey   string
	signer note.Signer
	// Cosigners, if set, add witness cosignatures to the live checkpoint (archives keep the log's
	// signature only, as the TypeScript writer does).
	Cosigners []note.Signer

	mu       sync.Mutex
	entries  [][]byte
	hashes   []tlog.Hash // stored hashes, tlog's layout
	files    map[string][]byte
	archives []int64
}

// New returns an empty log whose key is named after origin.
func New(t testing.TB, origin string) *Log {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatal(err)
	}
	return NewWithKey(t, origin, skey, vkey)
}

// NewWithKey returns an empty log signed with the given key, e.g. to build a fork of another log.
func NewWithKey(t testing.TB, origin, skey, vkey string) *Log {
	t.Helper()
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	return &Log{Origin: origin, VKey: vkey, SKey: skey, signer: signer, files: make(map[string][]byte)}
}

// Verifier returns the verifier for the log's key.
func (l *Log) Verifier(t testing.TB) note.Verifier {
	t.Helper()
	v, err := note.NewVerifier(l.VKey)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (l *Log) readHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, x := range indexes {
		if x < 0 || x >= int64(len(l.hashes)) {
			return nil, fmt.Errorf("hash %d not stored", x)
		}
		out[i] = l.hashes[x]
	}
	return out, nil
}

// tlogTilesPath maps Go's tile path (tile/8/<L>/<N>, tile/8/data/<N>) to tlog-tiles.
func tlogTilesPath(t tlog.Tile) string {
	p := strings.TrimPrefix(t.Path(), "tile/8/")
	if strings.HasPrefix(p, "data/") {
		return "tile/entries/" + strings.TrimPrefix(p, "data/")
	}
	return "tile/" + p
}

// Append adds entries and publishes the new size: tiles, bundles, an archived checkpoint and
// the live checkpoint. It returns the signed checkpoint.
func (l *Log) Append(t testing.TB, entries ...[]byte) []byte {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	old := int64(len(l.entries))
	for _, e := range entries {
		hs, err := tlog.StoredHashes(int64(len(l.entries)), e, tlog.HashReaderFunc(l.readHashes))
		if err != nil {
			t.Fatal(err)
		}
		l.hashes = append(l.hashes, hs...)
		l.entries = append(l.entries, e)
	}
	size := int64(len(l.entries))
	for _, tile := range tlog.NewTiles(8, old, size) {
		data, err := tlog.ReadTileData(tile, tlog.HashReaderFunc(l.readHashes))
		if err != nil {
			t.Fatal(err)
		}
		l.files[tlogTilesPath(tile)] = data
		if tile.L == 0 {
			bundle := tile
			bundle.L = -1
			var b []byte
			for _, e := range l.entries[tile.N*256 : tile.N*256+int64(tile.W)] {
				b = binary.BigEndian.AppendUint16(b, uint16(len(e)))
				b = append(b, e...)
			}
			l.files[tlogTilesPath(bundle)] = b
		}
	}
	l.files["x-checkpoints/"+strconv.FormatInt(size, 10)] = l.sign(t, size)
	cp := l.sign(t, size, l.Cosigners...)
	l.files["checkpoint"] = cp
	l.archives = append(l.archives, size)
	return cp
}

func (l *Log) sign(t testing.TB, size int64, cosigners ...note.Signer) []byte {
	t.Helper()
	root, err := tlog.TreeHash(size, tlog.HashReaderFunc(l.readHashes))
	if err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf("%s\n%d\n%s\n", l.Origin, size, base64.StdEncoding.EncodeToString(root[:]))
	msg, err := note.Sign(&note.Note{Text: text}, append([]note.Signer{l.signer}, cosigners...)...)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// Size is the number of entries.
func (l *Log) Size() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return int64(len(l.entries))
}

// Paths lists every resource currently published.
func (l *Log) Paths() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for p := range l.files {
		out = append(out, p)
	}
	return out
}

// File returns a copy of a published resource.
func (l *Log) File(path string) ([]byte, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.files[path]
	return append([]byte(nil), b...), ok
}

// SetFile replaces (or, with nil, removes) a published resource, e.g. to corrupt it.
func (l *Log) SetFile(path string, data []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if data == nil {
		delete(l.files, path)
		return
	}
	l.files[path] = data
}

// Server serves the log at <server URL>/log/test/. If token is non-empty, requests must carry
// it as a bearer token. The returned URL is the log prefix.
func (l *Log) Server(t testing.TB, token string) string {
	t.Helper()
	const prefix = "/log/test/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		data, ok := l.File(strings.TrimPrefix(r.URL.Path, prefix))
		if !ok || !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + strings.TrimSuffix(prefix, "/")
}

// Entry returns a JSON object entry with the given type, key and action, for tests.
func Entry(typ, key, action string) []byte {
	if action == "" {
		return fmt.Appendf(nil, `{"key":%q,"type":%q,"v":1}`, key, typ)
	}
	return fmt.Appendf(nil, `{"action":%q,"key":%q,"type":%q,"v":1}`, action, key, typ)
}

// Entries returns n distinct PutObject entries.
func Entries(start, n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = Entry("object.event", fmt.Sprintf("obj/%06d", start+i), "PutObject")
	}
	return out
}
