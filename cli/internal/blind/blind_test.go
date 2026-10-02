package blind

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// RFC 4231 §4.7 (test case 6): a 131-byte key of 0xaa; the TypeScript tests use the same vector.
func TestRFC4231(t *testing.T) {
	key, err := ParseKey(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xaa}, 131)))
	if err != nil {
		t.Fatal(err)
	}
	got := Name(key, "Test Using Larger Than Block-Size Key - Hash Key First")
	if want := "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestParseKeyRejects(t *testing.T) {
	ok := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if _, err := ParseKey(ok + "\n"); err != nil {
		t.Errorf("a trailing newline (as in a key file) must be accepted: %v", err)
	}
	for _, s := range []string{"", "short", ok + "=", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 32)),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 31))} {
		if _, err := ParseKey(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
