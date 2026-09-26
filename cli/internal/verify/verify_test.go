package verify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/isaiahfoster/r2notary/cli/internal/testlog"
	"github.com/isaiahfoster/r2notary/cli/internal/tilefetch"
	"github.com/isaiahfoster/r2notary/cli/internal/verr"
)

const origin = "example.com/log/test"

func b64(h []byte) string { return base64.StdEncoding.EncodeToString(h) }

func TestParseCheckpointText(t *testing.T) {
	root := bytes.Repeat([]byte{7}, 32)
	cp, err := ParseCheckpointText(origin + "\n42\n" + b64(root) + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if cp.Origin != origin || cp.Tree.N != 42 || !bytes.Equal(cp.Tree.Hash[:], root) {
		t.Fatalf("parsed %+v", cp)
	}
	if _, err := ParseCheckpointText(origin + "\n42\n" + b64(root) + "\next one\nanother\n"); err != nil {
		t.Errorf("extension lines: %v", err)
	}
	if cp, err := ParseCheckpointText(origin + "\n0\n" + b64(emptyRoot[:]) + "\n"); err != nil || cp.Tree.N != 0 {
		t.Errorf("empty tree: %v", err)
	}
	if _, err := ParseCheckpointText(origin + "\n9223372036854775807\n" + b64(root) + "\n"); err != nil {
		t.Errorf("max int64 size: %v", err)
	}
}

func TestParseCheckpointTextRejects(t *testing.T) {
	root := b64(bytes.Repeat([]byte{7}, 32))
	cases := map[string]string{
		"no final newline":       origin + "\n42\n" + root,
		"missing hash":           origin + "\n42\n",
		"empty origin":           "\n42\n" + root + "\n",
		"leading zero":           origin + "\n042\n" + root + "\n",
		"sign":                   origin + "\n+42\n" + root + "\n",
		"negative":               origin + "\n-1\n" + root + "\n",
		"size overflows int64":   origin + "\n9223372036854775808\n" + root + "\n",
		"short hash":             origin + "\n42\n" + b64(make([]byte, 31)) + "\n",
		"long hash":              origin + "\n42\n" + b64(make([]byte, 33)) + "\n",
		"unpadded base64":        origin + "\n42\n" + strings.TrimRight(root, "=") + "\n",
		"url-safe base64":        origin + "\n42\n" + b64(bytes.Repeat([]byte{0xfb}, 32)) + "\n",
		"empty extension line":   origin + "\n42\n" + root + "\n\n",
		"empty tree, wrong root": origin + "\n0\n" + root + "\n",
	}
	cases["url-safe base64"] = strings.NewReplacer("+", "-", "/", "_").Replace(cases["url-safe base64"])
	for name, text := range cases {
		if _, err := ParseCheckpointText(text); !verr.IsFailure(err) {
			t.Errorf("%s: err = %v, want a verification failure", name, err)
		}
	}
}

func TestOpenCheckpoint(t *testing.T) {
	l := testlog.New(t, origin)
	msg := l.Append(t, testlog.Entries(0, 3)...)
	v := l.Verifier(t)

	cp, err := OpenCheckpoint(msg, v, origin)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Tree.N != 3 || !bytes.Equal(cp.Note, msg) {
		t.Fatalf("opened %+v", cp)
	}

	other := testlog.New(t, origin) // same name, different key
	if _, err := OpenCheckpoint(msg, other.Verifier(t), origin); !verr.IsFailure(err) {
		t.Errorf("unknown key: %v", err)
	}
	if _, err := OpenCheckpoint(msg, v, "example.com/log/other"); !verr.IsFailure(err) {
		t.Errorf("wrong origin: %v", err)
	}
	// I7: a flipped bit anywhere in the note (text or signature) is rejected.
	for i := range len(msg) * 8 {
		bad := append([]byte(nil), msg...)
		bad[i/8] ^= 1 << (i % 8)
		if _, err := OpenCheckpoint(bad, v, origin); err == nil {
			t.Fatalf("bit %d flipped: accepted", i)
		} else if !verr.IsFailure(err) {
			t.Fatalf("bit %d flipped: %v is not a verification failure", i, err)
		}
	}
}

// Signed by the right key but with an origin that differs from the key name.
func TestOpenCheckpointOriginMustMatchText(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := note.NewSigner(skey)
	v, _ := note.NewVerifier(vkey)
	msg, err := note.Sign(&note.Note{Text: "example.com/log/other\n0\n" + b64(emptyRoot[:]) + "\n"}, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCheckpoint(msg, v, origin); !verr.IsFailure(err) || !strings.Contains(err.Error(), "origin") {
		t.Fatalf("err = %v", err)
	}
}

func newLog(t *testing.T, l *testlog.Log) *Log {
	t.Helper()
	c, err := tilefetch.NewClient(l.Server(t, ""), "")
	if err != nil {
		t.Fatal(err)
	}
	return &Log{Client: c, Verifier: l.Verifier(t), Origin: origin}
}

func TestInclusionAtEdgeSizes(t *testing.T) {
	ctx := context.Background()
	for _, size := range []int{1, 2, 255, 256, 257, 511, 512, 513, 65535, 65536, 65537, 70000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			l := testlog.New(t, origin)
			entries := testlog.Entries(0, size)
			l.Append(t, entries...)
			lg := newLog(t, l)
			cp, err := lg.Checkpoint(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if cp.Tree.N != int64(size) {
				t.Fatalf("size %d", cp.Tree.N)
			}
			for _, i := range []int{0, size / 2, size - 1, size - 256, 255, 256} {
				if i < 0 || i >= size {
					continue
				}
				got, err := lg.Inclusion(ctx, cp, int64(i))
				if err != nil {
					t.Fatalf("index %d: %v", i, err)
				}
				if !bytes.Equal(got.Entry, entries[i]) {
					t.Fatalf("index %d: entry %q", i, got.Entry)
				}
			}
			if _, err := lg.Inclusion(ctx, cp, int64(size)); err == nil || verr.IsFailure(err) {
				t.Fatalf("index == size: %v", err)
			}
		})
	}
}

func TestEntriesVerifiesEveryEntry(t *testing.T) {
	ctx := context.Background()
	l := testlog.New(t, origin)
	entries := testlog.Entries(0, 700)
	l.Append(t, entries...)
	lg := newLog(t, l)
	cp, err := lg.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got [][]byte
	err = lg.Entries(ctx, cp, 100, 600, func(i int64, e []byte) error {
		if i != int64(100+len(got)) {
			return fmt.Errorf("index %d out of order", i)
		}
		got = append(got, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 500 || !bytes.Equal(got[0], entries[100]) || !bytes.Equal(got[499], entries[599]) {
		t.Fatalf("got %d entries", len(got))
	}
	stop := errors.New("stop")
	if err := lg.Entries(ctx, cp, 0, 700, func(int64, []byte) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("callback error not returned: %v", err)
	}
	if err := lg.Entries(ctx, cp, 0, 701, nil); err == nil {
		t.Fatal("range beyond the tree accepted")
	}
}

// resourcesAt lists every resource a verifier reads for a full scan of a tree of size n: each
// hash tile and entry bundle of that size, and the checkpoint. tlog.NewTiles(8, 0, n) is exactly
// the set of tiles of a tree of size n.
func resourcesAt(n int64) []string {
	paths := []string{"checkpoint"}
	for _, tile := range tlog.NewTiles(8, 0, n) {
		p, err := tilefetch.TilePath(tile)
		if err != nil {
			panic(err)
		}
		paths = append(paths, p)
		if tile.L == 0 {
			paths = append(paths, tilefetch.BundlePath(tile.N, tile.W))
		}
	}
	return paths
}

// I7 (Go side): a single flipped bit in any resource of the tree makes a full scan fail with a
// verification failure. Bits are sampled at the start, middle and end of each resource.
func TestEntriesRejectsAnyFlippedBit(t *testing.T) {
	ctx := context.Background()
	l := testlog.New(t, origin)
	l.Append(t, testlog.Entries(0, 300)...)
	l.Append(t, testlog.Entries(300, 400)...) // two checkpoints, so old partials exist too
	lg := newLog(t, l)
	scan := func() error {
		cp, err := lg.Checkpoint(ctx)
		if err != nil {
			return err
		}
		return lg.Entries(ctx, cp, 0, cp.Tree.N, func(int64, []byte) error { return nil })
	}
	if err := scan(); err != nil {
		t.Fatal(err)
	}
	paths := resourcesAt(700)
	// checkpoint; tiles 0/000, 0/001, 0/002.p/188, 1/000.p/2; bundles 000, 001, 002.p/188
	if len(paths) != 8 {
		t.Fatalf("resources: %v", paths)
	}
	for _, p := range paths {
		orig, ok := l.File(p)
		if !ok {
			t.Fatalf("%s not published", p)
		}
		for _, bit := range []int{0, len(orig) * 4, len(orig)*8 - 1} {
			bad := append([]byte(nil), orig...)
			bad[bit/8] ^= 1 << (bit % 8)
			l.SetFile(p, bad)
			lg.Client, _ = tilefetch.NewClient(l.Server(t, ""), "") // drop cached tiles
			if err := scan(); !verr.IsFailure(err) {
				t.Errorf("%s bit %d: err = %v, want a verification failure", p, bit, err)
			}
		}
		l.SetFile(p, orig)
	}
	// Truncated and extended resources are rejected too.
	for _, p := range paths[1:] {
		orig, _ := l.File(p)
		for _, bad := range [][]byte{orig[:len(orig)-1], append(append([]byte(nil), orig...), 0)} {
			l.SetFile(p, bad)
			lg.Client, _ = tilefetch.NewClient(l.Server(t, ""), "")
			if err := scan(); !verr.IsFailure(err) {
				t.Errorf("%s resized to %d: err = %v", p, len(bad), err)
			}
		}
		l.SetFile(p, orig)
	}
}

func TestMissingResourceIsNotAFailure(t *testing.T) {
	ctx := context.Background()
	l := testlog.New(t, origin)
	l.Append(t, testlog.Entries(0, 10)...)
	lg := newLog(t, l)
	cp, err := lg.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	l.SetFile("tile/0/000.p/10", nil)
	_, err = lg.Inclusion(ctx, cp, 3)
	var fe *tilefetch.FetchError
	if !errors.As(err, &fe) || fe.Status != 404 || verr.IsFailure(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestConsistency(t *testing.T) {
	ctx := context.Background()
	l := testlog.New(t, origin)
	var notes [][]byte
	for _, n := range []int{1, 255, 1, 256, 300, 1} { // sizes 1, 256, 257, 513, 813, 814
		notes = append(notes, l.Append(t, testlog.Entries(int(l.Size()), n)...))
	}
	lg := newLog(t, l)
	open := func(msg []byte) *Checkpoint {
		cp, err := OpenCheckpoint(msg, lg.Verifier, origin)
		if err != nil {
			t.Fatal(err)
		}
		return cp
	}
	// I3 (Go side): every pair of archived checkpoints is consistent, using the tiles of the newer.
	for i := range notes {
		for j := i; j < len(notes); j++ {
			if err := lg.Consistency(ctx, open(notes[i]), open(notes[j])); err != nil {
				t.Errorf("%d -> %d: %v", i, j, err)
			}
		}
	}
	if err := lg.Consistency(ctx, open(notes[3]), open(notes[1])); !verr.IsFailure(err) {
		t.Errorf("regression: %v", err)
	}

	// A fork: same key, same first 256 entries, different entry 256.
	fork := testlog.New(t, origin)
	fork.Append(t, testlog.Entries(0, 256)...)
	fork.Append(t, testlog.Entry("object.event", "forked", "DeleteObject"))
	forkNote := fork.Append(t, testlog.Entries(257, 300)...)
	// The fork has its own key here; what matters is that its root at size 557 is not the real
	// log's, so the real log's tiles cannot prove 557 -> 813 from it.
	forked, err := OpenCheckpoint(forkNote, fork.Verifier(t), origin)
	if err != nil {
		t.Fatal(err)
	}
	if err := lg.Consistency(ctx, forked, open(notes[4])); !verr.IsFailure(err) {
		t.Errorf("fork (size 557 -> 813): %v", err)
	}
	same := *open(notes[2])
	same.Tree.Hash[0] ^= 1
	if err := lg.Consistency(ctx, &same, open(notes[2])); !verr.IsFailure(err) {
		t.Errorf("same size, different root: %v", err)
	}
	empty := &Checkpoint{Origin: origin, Tree: tlog.Tree{N: 0, Hash: emptyRoot}}
	if err := lg.Consistency(ctx, empty, open(notes[0])); err != nil {
		t.Errorf("empty -> 1: %v", err)
	}
}
