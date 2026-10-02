// Package cosign implements C2SP tlog-cosignature Ed25519 cosignatures (`cosignature/v1`,
// signature type 0x04): the signatures witnesses add to a log's checkpoints. Verifier plugs into
// golang.org/x/mod/sumdb/note, so note.Open checks the log's signature and the cosignatures in
// one pass. Written from the specification; it shares no code with the TypeScript writer.
//
// The signed message is "cosignature/v1\ntime <t>\n" followed by the checkpoint text, and the
// signature is a big-endian uint64 timestamp followed by the 64-byte Ed25519 signature. Keys use
// the vkey format with type byte 0x04, which also enters the key ID, so a cosigner key never
// matches a log key.
package cosign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/mod/sumdb/note"
)

// AlgCosignatureV1 is the signature type byte of Ed25519 cosignature/v1 keys.
const AlgCosignatureV1 = 0x04

const timestampSize = 8

// keyHash is SHA-256(name || "\n" || 0x04 || public key)[:4], big-endian.
func keyHash(name string, pub ed25519.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', AlgCosignatureV1})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// validName follows the signed-note rules: non-empty, valid UTF-8, no Unicode spaces or '+'.
func validName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 &&
		!strings.Contains(name, "+")
}

func message(t uint64, text []byte) []byte {
	return append([]byte("cosignature/v1\ntime "+strconv.FormatUint(t, 10)+"\n"), text...)
}

// splitKey parses name+hash+base64(0x04||material) and checks the type byte and length.
func splitKey(key string, size int) (name string, hash uint32, material []byte, err error) {
	name, rest, ok1 := strings.Cut(key, "+")
	hash16, b64, ok2 := strings.Cut(rest, "+")
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	if !ok1 || !ok2 || err != nil || !validName(name) || len(hash16) != 8 || len(raw) != 1+size ||
		raw[0] != AlgCosignatureV1 || base64.StdEncoding.EncodeToString(raw) != b64 {
		return "", 0, nil, errors.New("malformed cosigner key")
	}
	h, err := strconv.ParseUint(hash16, 16, 32)
	if err != nil {
		return "", 0, nil, errors.New("malformed cosigner key hash")
	}
	return name, uint32(h), raw[1:], nil
}

// Verifier verifies cosignature/v1 signatures by one cosigner key.
type Verifier struct {
	name string
	hash uint32
	key  ed25519.PublicKey
}

var _ note.Verifier = (*Verifier)(nil)

// NewVerifier parses a cosigner verifier key (vkey with type 0x04) and checks its key hash.
func NewVerifier(vkey string) (*Verifier, error) {
	name, hash, pub, err := splitKey(vkey, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	if keyHash(name, pub) != hash {
		return nil, errors.New("cosigner key hash does not match name and key")
	}
	return &Verifier{name: name, hash: hash, key: pub}, nil
}

func (v *Verifier) Name() string    { return v.name }
func (v *Verifier) KeyHash() uint32 { return v.hash }

// Verify checks sig (timestamp || signature, without the key hash) over the note text msg.
func (v *Verifier) Verify(msg, sig []byte) bool {
	if len(sig) != timestampSize+ed25519.SignatureSize {
		return false
	}
	t := binary.BigEndian.Uint64(sig)
	return ed25519.Verify(v.key, message(t, msg), sig[timestampSize:])
}

// Timestamp returns the time (POSIX seconds) of a cosignature from note.Open's Sigs.
func Timestamp(s note.Signature) (uint64, error) {
	raw, err := base64.StdEncoding.DecodeString(s.Base64)
	if err != nil || len(raw) != 4+timestampSize+ed25519.SignatureSize {
		return 0, fmt.Errorf("signature from %s is not a cosignature", s.Name)
	}
	return binary.BigEndian.Uint64(raw[4:]), nil
}

// Signer cosigns note text with a cosigner key, at the time its clock returns. The CLI does not
// cosign anything; this exists for tests and for anyone running a witness with Go tooling.
type Signer struct {
	name  string
	hash  uint32
	key   ed25519.PrivateKey
	clock func() time.Time
}

var _ note.Signer = (*Signer)(nil)

// NewSigner parses a PRIVATE+KEY+name+hash+base64(0x04||seed) key.
func NewSigner(skey string, clock func() time.Time) (*Signer, error) {
	rest, ok := strings.CutPrefix(skey, "PRIVATE+KEY+")
	if !ok {
		return nil, errors.New("malformed cosigner signer key")
	}
	name, hash, seed, err := splitKey(rest, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	key := ed25519.NewKeyFromSeed(seed)
	if keyHash(name, key.Public().(ed25519.PublicKey)) != hash {
		return nil, errors.New("cosigner key hash does not match name and key")
	}
	return &Signer{name: name, hash: hash, key: key, clock: clock}, nil
}

func (s *Signer) Name() string    { return s.name }
func (s *Signer) KeyHash() uint32 { return s.hash }

// Sign returns timestamp || Ed25519 signature over the cosigned message.
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	t := s.clock().Unix()
	if t <= 0 {
		return nil, errors.New("cosignature time must be after 1970")
	}
	out := binary.BigEndian.AppendUint64(nil, uint64(t))
	return append(out, ed25519.Sign(s.key, message(uint64(t), msg))...), nil
}

// GenerateKey returns a new cosigner key pair as signer and verifier key strings.
func GenerateKey(r io.Reader, name string) (skey, vkey string, err error) {
	if !validName(name) {
		return "", "", fmt.Errorf("invalid key name %q", name)
	}
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return "", "", err
	}
	h := fmt.Sprintf("%08x", keyHash(name, pub))
	enc := func(b []byte) string {
		return base64.StdEncoding.EncodeToString(append([]byte{AlgCosignatureV1}, b...))
	}
	return "PRIVATE+KEY+" + name + "+" + h + "+" + enc(priv.Seed()), name + "+" + h + "+" + enc(pub), nil
}
