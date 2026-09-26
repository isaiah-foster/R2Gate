// Package verify checks an R2Notary log: checkpoint signatures (C2SP signed-note,
// tlog-checkpoint), inclusion of entries, and consistency between checkpoints. Every proof is
// computed locally from tiles; tlog.TileHashReader authenticates each tile against the signed
// tree hash before any hash from it is used. The server is trusted for nothing but availability.
package verify

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/isaiahfoster/r2notary/cli/internal/tilefetch"
	"github.com/isaiahfoster/r2notary/cli/internal/verr"
)

// Checkpoint is a signed checkpoint whose signature and origin have been verified.
type Checkpoint struct {
	Origin string
	Tree   tlog.Tree
	// Note is the signed note exactly as received, suitable for saving and re-verifying.
	Note []byte
}

// emptyRoot is the RFC 6962 hash of an empty tree, SHA-256 of nothing.
var emptyRoot = tlog.Hash(sha256.Sum256(nil))

// ParseCheckpointText parses checkpoint text (C2SP tlog-checkpoint): origin, decimal tree size and
// base64 root hash, one per line, then optional extension lines, which are ignored. The text is
// what note.Open returns, so it ends in a newline. The returned Checkpoint has no Note.
func ParseCheckpointText(text string) (*Checkpoint, error) {
	if !strings.HasSuffix(text, "\n") {
		return nil, verr.Failf("checkpoint does not end in a newline")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 {
		return nil, verr.Failf("checkpoint has %d lines, want at least 3", len(lines))
	}
	for i, l := range lines[3:] {
		if l == "" {
			return nil, verr.Failf("checkpoint extension line %d is empty", i+1)
		}
	}
	origin, sizeStr, hashStr := lines[0], lines[1], lines[2]
	if origin == "" {
		return nil, verr.Failf("checkpoint origin is empty")
	}
	// Decimal without leading zeros or sign: a size has one spelling.
	if sizeStr == "" || (len(sizeStr) > 1 && sizeStr[0] == '0') || strings.TrimLeft(sizeStr, "0123456789") != "" {
		return nil, verr.Failf("checkpoint size %q is not a decimal number", sizeStr)
	}
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return nil, verr.Failf("checkpoint size %q: %v", sizeStr, err)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(hashStr)
	if err != nil || len(raw) != tlog.HashSize || base64.StdEncoding.EncodeToString(raw) != hashStr {
		return nil, verr.Failf("checkpoint root hash %q is not 32 bytes of standard base64", hashStr)
	}
	cp := &Checkpoint{Origin: origin, Tree: tlog.Tree{N: size, Hash: tlog.Hash(raw)}}
	if size == 0 && cp.Tree.Hash != emptyRoot {
		return nil, verr.Failf("checkpoint for an empty tree has root %s, want SHA-256 of nothing", hashStr)
	}
	return cp, nil
}

// OpenCheckpoint verifies msg as a signed note from v and parses its text as a checkpoint whose
// origin must equal origin (I9). The signed-note rules are note.Open's: signatures from other
// keys are ignored, but one from v that does not verify rejects the note.
func OpenCheckpoint(msg []byte, v note.Verifier, origin string) (*Checkpoint, error) {
	n, err := note.Open(msg, note.VerifierList(v))
	if err != nil {
		var unverified *note.UnverifiedNoteError
		if errors.As(err, &unverified) {
			return nil, verr.Failf("checkpoint has no valid signature from %s", v.Name())
		}
		return nil, verr.Failf("checkpoint signature: %v", err)
	}
	// note.Open decodes signatures with lenient base64, which ignores the unused low bits of the
	// last character, so one signature has several spellings. Accept only the canonical one, as
	// the TypeScript writer does (DECISIONS D1.9): a note then has exactly one valid encoding.
	for _, s := range n.Sigs {
		raw, err := base64.StdEncoding.DecodeString(s.Base64)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != s.Base64 {
			return nil, verr.Failf("checkpoint signature from %s is not canonical base64", s.Name)
		}
	}
	cp, err := ParseCheckpointText(n.Text)
	if err != nil {
		return nil, err
	}
	if cp.Origin != origin {
		return nil, verr.Failf("checkpoint origin is %q, want %q", cp.Origin, origin)
	}
	cp.Note = msg
	return cp, nil
}

// Log is a log to verify: where it is served, the key that signs it, and its expected origin.
type Log struct {
	Client   *tilefetch.Client
	Verifier note.Verifier
	Origin   string
}

// Checkpoint fetches and verifies the live checkpoint.
func (l *Log) Checkpoint(ctx context.Context) (*Checkpoint, error) {
	msg, err := l.Client.Get(ctx, "checkpoint", tilefetch.MaxCheckpointSize)
	if err != nil {
		return nil, err
	}
	return OpenCheckpoint(msg, l.Verifier, l.Origin)
}

// classify turns an error from tlog into a verification failure unless it is a fetch error
// (nothing wrong was received) or already classified. tlog reports bad tiles as plain errors
// ("downloaded inconsistent tile").
func classify(err error) error {
	var fe *tilefetch.FetchError
	if err == nil || errors.As(err, &fe) {
		return err
	}
	return verr.Fail(err)
}

func (l *Log) hashReader(ctx context.Context, cp *Checkpoint) tlog.HashReader {
	return tlog.TileHashReader(cp.Tree, l.Client.TileReader(ctx))
}

// IndexError reports an index outside the tree. It is a usage error, not a failure.
type IndexError struct {
	Index, Size int64
}

func (e *IndexError) Error() string {
	return fmt.Sprintf("index %d is not in a tree of size %d", e.Index, e.Size)
}

// Included is a verified entry.
type Included struct {
	Index int64
	Entry []byte
	// ProofHashes is the number of hashes in the inclusion proof.
	ProofHashes int
}

// Inclusion fetches entry index from its bundle and proves it is in cp's tree: the RFC 6962
// inclusion proof is built from authenticated tiles and checked against cp's root hash.
func (l *Log) Inclusion(ctx context.Context, cp *Checkpoint, index int64) (*Included, error) {
	if index < 0 || index >= cp.Tree.N {
		return nil, &IndexError{Index: index, Size: cp.Tree.N}
	}
	n := index / tilefetch.Width
	entries, err := l.Client.Bundle(ctx, n, tilefetch.BundleWidth(n, cp.Tree.N))
	if err != nil {
		return nil, err
	}
	entry := entries[index%tilefetch.Width]
	proof, err := tlog.ProveRecord(cp.Tree.N, index, l.hashReader(ctx, cp))
	if err != nil {
		return nil, classify(err)
	}
	if err := tlog.CheckRecord(proof, cp.Tree.N, cp.Tree.Hash, index, tlog.RecordHash(entry)); err != nil {
		return nil, verr.Failf("entry %d is not in the tree of size %d: %v", index, cp.Tree.N, err)
	}
	return &Included{Index: index, Entry: entry, ProofHashes: len(proof)}, nil
}

// Entries verifies every entry with index in [from, to) and calls fn for each, in order. Each
// bundle it touches is checked whole: every entry's leaf hash must equal the hash in the
// authenticated level-0 tile, so a flipped bit anywhere in a bundle is caught. An error from fn
// stops the scan and is returned as is.
func (l *Log) Entries(ctx context.Context, cp *Checkpoint, from, to int64, fn func(index int64, entry []byte) error) error {
	if from < 0 || to > cp.Tree.N || from > to {
		return fmt.Errorf("range [%d, %d) is not within a tree of size %d", from, to, cp.Tree.N)
	}
	hr := l.hashReader(ctx, cp)
	for n := from / tilefetch.Width; n*tilefetch.Width < to; n++ {
		w := tilefetch.BundleWidth(n, cp.Tree.N)
		entries, err := l.Client.Bundle(ctx, n, w)
		if err != nil {
			return err
		}
		first := n * tilefetch.Width
		indexes := make([]int64, w)
		for k := range indexes {
			indexes[k] = tlog.StoredHashIndex(0, first+int64(k))
		}
		hashes, err := hr.ReadHashes(indexes)
		if err != nil {
			return classify(err)
		}
		for k, e := range entries {
			if tlog.RecordHash(e) != hashes[k] {
				return verr.Failf("%s: entry %d does not match the tree", tilefetch.BundlePath(n, w), first+int64(k))
			}
		}
		for k, e := range entries {
			i := first + int64(k)
			if i < from || i >= to || fn == nil {
				continue
			}
			if err := fn(i, e); err != nil {
				return err
			}
		}
	}
	return nil
}

// Consistency proves that newer's tree extends older's (RFC 6962 consistency proof, built from
// newer's authenticated tiles). A smaller newer tree, or the same size with another root, is a
// verification failure: a rollback or a fork.
func (l *Log) Consistency(ctx context.Context, older, newer *Checkpoint) error {
	o, n := older.Tree, newer.Tree
	switch {
	case o.N > n.N:
		return verr.Failf("tree size went backwards: %d after %d", n.N, o.N)
	case o.N == n.N:
		if o.Hash != n.Hash {
			return verr.Failf("two different trees of size %d: roots %s and %s", o.N, o.Hash, n.Hash)
		}
		return nil
	case o.N == 0:
		return nil // the empty tree (root checked when parsed) is a prefix of every tree
	}
	proof, err := tlog.ProveTree(n.N, o.N, l.hashReader(ctx, newer))
	if err != nil {
		return classify(err)
	}
	if err := tlog.CheckTree(proof, n.N, n.Hash, o.N, o.Hash); err != nil {
		return verr.Failf("tree of size %d (root %s) is not an extension of tree of size %d (root %s): %v",
			n.N, n.Hash, o.N, o.Hash, err)
	}
	return nil
}
