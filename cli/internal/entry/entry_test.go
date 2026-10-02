package entry

import (
	"testing"
)

func TestParse(t *testing.T) {
	put := Parse([]byte(`{"action":"PutObject","bucket":"b","eventTime":"2026-01-01T00:00:00Z","key":"a/b","type":"object.event","v":1}`))
	if !put.Known() || !put.IsWrite() || put.IsDelete() || put.Key != "a/b" || !put.HasKey {
		t.Errorf("put: %+v", put)
	}
	del := Parse([]byte(`{"action":"LifecycleDeletion","key":"k","type":"object.event","v":1}`))
	if !del.IsDelete() || del.IsWrite() {
		t.Errorf("delete: %+v", del)
	}
	snap := Parse([]byte(`{"key":"k","type":"object.snapshot","v":1}`))
	if !snap.IsSnapshot() || snap.IsWrite() {
		t.Errorf("snapshot: %+v", snap)
	}
	blinded := Parse([]byte(`{"action":"PutObject","keyHmac":"abc","type":"object.event","v":1}`))
	if !blinded.IsWrite() || blinded.HasKey || !blinded.HasKeyHmac || blinded.KeyHmac != "abc" {
		t.Errorf("blinded: %+v", blinded)
	}
	scan := Parse([]byte(`{"phase":"start","scanId":"s","type":"audit.scan","v":1}`))
	if !scan.Known() || scan.HasKey {
		t.Errorf("scan: %+v", scan)
	}
}

func TestParseUnknownAndMalformed(t *testing.T) {
	future := Parse([]byte(`{"action":"DeleteObject","key":"k","type":"object.event","v":2}`))
	if !future.Valid || future.Known() || future.IsDelete() {
		t.Errorf("v2 must not be interpreted: %+v", future)
	}
	other := Parse([]byte(`{"type":"something.new","v":1}`))
	if !other.Valid || other.Known() {
		t.Errorf("unknown type: %+v", other)
	}
	for _, b := range []string{`[]`, `"x"`, `{"type":"object.event"}`, `{"v":"1","type":"object.event"}`, `{"v":1.5,"type":"object.event"}`, `not json`} {
		if info := Parse([]byte(b)); info.Valid || info.Known() {
			t.Errorf("%s: %+v", b, info)
		}
	}
	// Field names match exactly.
	if info := Parse([]byte(`{"KEY":"k","Type":"object.event","v":1}`)); info.HasKey || info.Valid {
		t.Errorf("case-insensitive match: %+v", info)
	}
}

func TestLine(t *testing.T) {
	if got := string(Line(7, []byte(`{"v":1}`))); got != `{"index":7,"entry":{"v":1}}` {
		t.Errorf("valid: %s", got)
	}
	if got := string(Line(8, []byte("\xff{"))); got != `{"index":8,"entry":"�{"}` {
		t.Errorf("invalid: %s", got)
	}
}
