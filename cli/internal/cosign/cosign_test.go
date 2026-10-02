package cosign

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

// A vector produced by a third-party implementation, github.com/transparency-dev/formats v0.1.1
// (NewSignerForCosignatureV1), with golang.org/x/mod/sumdb/note for the log signature, from fixed
// seeds. Data only; the TypeScript tests use the same vector (packages/core/test).
const (
	vecLogVKey  = "example.com/vector-log+4516a1da+ARGkVJ4QEa2MOOLGBO6i7NVSJ1FQ97tIX+w+Ku0RZ6Em"
	vecWitSKey  = "PRIVATE+KEY+witness.example.com/vector+416f103d+BJEX3xv88eoQIKT4E+GkxZcXaJCYlQfi/GJ3NDFmZIW8"
	vecWitVKey  = "witness.example.com/vector+416f103d+BK/QmJFVP3SKJOqAMhFxBQPtylo3sjwWibyFDAlZKK8B"
	vecText     = "example.com/vector-log\n1234\nSBNJTRN+FjG7owHVrKtue7eqdM4RhdRWVl71HXN2d7I=\n"
	vecLogLine  = "— example.com/vector-log RRah2qlLrSlk6J8DA1HmNewppUM15Quhs5cAIb1KjBsV3otVirJTW8AFVsQtJkTW1Zny7GuoAxZpI6bUPcpM68QOIgE=\n"
	vecWitLine  = "— witness.example.com/vector QW8QPQAAAABqwLUbDdj7sDNRIVjmjYgqFI6y4UJhPg/UAA8J8wAdqSd3q4PedRhkgXA4xFN/Jg5uWn7ZkBA+H/UHQs5d9hITdXmQAA==\n"
	vecTime     = 1791014171
	vecWitKeyID = 0x416f103d
)

func vecNote() []byte { return []byte(vecText + "\n" + vecLogLine + vecWitLine) }

func TestThirdPartyVector(t *testing.T) {
	logV, err := note.NewVerifier(vecLogVKey)
	if err != nil {
		t.Fatal(err)
	}
	witV, err := NewVerifier(vecWitVKey)
	if err != nil {
		t.Fatal(err)
	}
	if witV.Name() != "witness.example.com/vector" || witV.KeyHash() != vecWitKeyID {
		t.Fatalf("name %q, key hash %08x", witV.Name(), witV.KeyHash())
	}
	n, err := note.Open(vecNote(), note.VerifierList(logV, witV))
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Sigs) != 2 {
		t.Fatalf("%d verified signatures, want 2", len(n.Sigs))
	}
	ts, err := Timestamp(n.Sigs[1])
	if err != nil || ts != vecTime {
		t.Fatalf("timestamp %d, %v; want %d", ts, err, vecTime)
	}
}

func TestSignerReproducesVector(t *testing.T) {
	s, err := NewSigner(vecWitSKey, func() time.Time { return time.Unix(vecTime, 0) })
	if err != nil {
		t.Fatal(err)
	}
	signed, err := note.Sign(&note.Note{Text: vecText}, s)
	if err != nil {
		t.Fatal(err)
	}
	if want := vecText + "\n" + vecWitLine; string(signed) != want {
		t.Fatalf("got\n%s\nwant\n%s", signed, want)
	}
}

func TestRejectsTampering(t *testing.T) {
	witV, _ := NewVerifier(vecWitVKey)
	tampered := strings.Replace(string(vecNote()), "1234", "1235", 1)
	_, err := note.Open([]byte(tampered), note.VerifierList(witV))
	var inv *note.InvalidSignatureError
	if !errors.As(err, &inv) {
		t.Fatalf("tampered text: %v, want an invalid signature", err)
	}
	// The timestamp is signed: changing it breaks the signature. Byte 11 is the timestamp's last.
	raw := []byte(vecWitLine)
	i := strings.LastIndexByte(vecWitLine, ' ') + 1 + 12 // base64 of bytes 9..11
	raw[i] = 'B'
	if _, err := note.Open([]byte(vecText+"\n"+string(raw)), note.VerifierList(witV)); err == nil {
		t.Fatal("changed timestamp still verifies")
	}
}

func TestKeyTypes(t *testing.T) {
	if _, err := NewVerifier(vecLogVKey); err == nil {
		t.Error("a log key (type 0x01) was accepted as a cosigner key")
	}
	if _, err := note.NewVerifier(vecWitVKey); err == nil {
		t.Error("x/mod/sumdb/note accepted a cosigner key as a log key")
	}
	for _, bad := range []string{"", "a+b+c", "witness+416f103d+BK/QmJFVP3SKJOqAMhFxBQPtylo3sjwWibyFDAlZKK8B",
		strings.Replace(vecWitVKey, "+BK/", "+BB/", 1)} {
		if _, err := NewVerifier(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := NewSigner("PRIVATE+KEY+example.com/vector-log+4516a1da+ARnX7cNOLM36CVoVFnmyY1Yp3SE+vpow5cbV4Sw8rjRE", time.Now); err == nil {
		t.Error("a log signer key was accepted as a cosigner key")
	}
}

func TestGenerateKeyRoundTrip(t *testing.T) {
	skey, vkey, err := GenerateKey(rand.Reader, "witness.example/w1")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(skey, func() time.Time { return time.Unix(1_700_000_000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := note.Sign(&note.Note{Text: vecText}, s)
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Open(signed, note.VerifierList(v))
	if err != nil {
		t.Fatal(err)
	}
	if ts, err := Timestamp(n.Sigs[0]); err != nil || ts != 1_700_000_000 {
		t.Fatalf("timestamp %d, %v", ts, err)
	}
	if _, err := Timestamp(note.Signature{Base64: "AAAA"}); err == nil {
		t.Error("a 3-byte signature has no timestamp")
	}
}
