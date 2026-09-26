package tilefetch

import (
	"bytes"
	"testing"

	"github.com/isaiahfoster/r2notary/cli/internal/verr"
)

func TestParseBundle(t *testing.T) {
	data := []byte{0, 1, 'a', 0, 0, 0, 3, 'x', 'y', 'z'}
	got, err := ParseBundle(data, 3)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]byte{[]byte("a"), {}, []byte("xyz")}
	if len(got) != len(want) {
		t.Fatalf("got %d entries", len(got))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseBundleMaxEntry(t *testing.T) {
	entry := bytes.Repeat([]byte{'e'}, 0xffff)
	got, err := ParseBundle(append([]byte{0xff, 0xff}, entry...), 1)
	if err != nil || len(got) != 1 || !bytes.Equal(got[0], entry) {
		t.Fatalf("65,535-byte entry: %v", err)
	}
}

func TestParseBundleRejects(t *testing.T) {
	cases := map[string]struct {
		data  []byte
		width int
	}{
		"too few entries":  {[]byte{0, 1, 'a'}, 2},
		"too many entries": {[]byte{0, 1, 'a', 0, 1, 'b'}, 1},
		"trailing byte":    {[]byte{0, 1, 'a', 0}, 1},
		"truncated entry":  {[]byte{0, 3, 'a', 'b'}, 1},
		"truncated prefix": {[]byte{0}, 1},
		"empty":            {nil, 1},
	}
	for name, c := range cases {
		if _, err := ParseBundle(c.data, c.width); !verr.IsFailure(err) {
			t.Errorf("%s: err = %v, want a verification failure", name, err)
		}
	}
}
