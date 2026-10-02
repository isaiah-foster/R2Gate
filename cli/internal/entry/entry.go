// Package entry reads the few fields of an R2Notary log entry (PLAN §5.2) that the CLI acts on.
// It does not validate the entry schema: verification is about the bytes the log committed to,
// and an entry of an unknown type or version is printed and otherwise skipped.
package entry

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Info is what the CLI uses from an entry. Fields absent or of the wrong JSON type are empty.
type Info struct {
	// Valid is false if the entry is not a JSON object with an integer "v" and a string "type".
	Valid  bool
	V      int64
	Type   string
	Key    string
	HasKey bool
	// KeyHmac names the object on a blinded log (M8) instead of Key.
	KeyHmac    string
	HasKeyHmac bool
	Action     string
	// Auditor fields (audit.finding, audit.scan).
	ScanID      string
	Phase       string
	Kind        string
	Findings    int64
	HasFindings bool
}

// Parse reads an entry. Field names are matched exactly (encoding/json's struct decoding would
// also match "KEY" or "Key").
func Parse(b []byte) Info {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return Info{}
	}
	var info Info
	str := func(name string) (string, bool) {
		var s string
		raw, ok := m[name]
		if !ok || json.Unmarshal(raw, &s) != nil {
			return "", false
		}
		return s, true
	}
	if raw, ok := m["v"]; ok && json.Unmarshal(raw, &info.V) == nil {
		info.Type, info.Valid = str("type")
	}
	info.Key, info.HasKey = str("key")
	info.KeyHmac, info.HasKeyHmac = str("keyHmac")
	info.Action, _ = str("action")
	info.ScanID, _ = str("scanId")
	info.Phase, _ = str("phase")
	info.Kind, _ = str("kind")
	if raw, ok := m["findings"]; ok {
		info.HasFindings = json.Unmarshal(raw, &info.Findings) == nil
	}
	return info
}

// Known reports whether the CLI understands this entry's type and version.
func (i Info) Known() bool {
	if !i.Valid || i.V != 1 {
		return false
	}
	switch i.Type {
	case "object.event", "object.snapshot", "audit.finding", "audit.scan", "audit.observation":
		return true
	}
	return false
}

// IsDelete reports whether the entry records an object deletion.
func (i Info) IsDelete() bool {
	return i.Valid && i.V == 1 && i.Type == "object.event" &&
		(i.Action == "DeleteObject" || i.Action == "LifecycleDeletion")
}

// IsWrite reports whether the entry records an object being created or replaced.
func (i Info) IsWrite() bool {
	return i.Valid && i.V == 1 && i.Type == "object.event" &&
		(i.Action == "PutObject" || i.Action == "CopyObject" || i.Action == "CompleteMultipartUpload")
}

// IsFinding reports whether the entry is an auditor finding of the given scan.
func (i Info) IsFinding(scanID string) bool {
	return i.Valid && i.V == 1 && i.Type == "audit.finding" && i.ScanID == scanID
}

// IsScan reports whether the entry is the given scan's audit.scan entry for phase.
func (i Info) IsScan(scanID, phase string) bool {
	return i.Valid && i.V == 1 && i.Type == "audit.scan" && i.ScanID == scanID && i.Phase == phase
}

// IsSnapshot reports whether the entry is a backfill snapshot of an existing object.
func (i Info) IsSnapshot() bool {
	return i.Valid && i.V == 1 && i.Type == "object.snapshot"
}

// Line formats an entry for output as one JSON line, {"index":N,"entry":...}. A valid JSON entry
// is embedded byte for byte (json.Marshal would rewrite it: it HTML-escapes <, > and &), so the
// output contains exactly the bytes the log committed to. Anything else is embedded as a string.
func Line(index int64, b []byte) []byte {
	if !json.Valid(b) || bytes.ContainsAny(b, "\n\r") {
		b, _ = json.Marshal(string(b))
	}
	out := fmt.Appendf(nil, `{"index":%d,"entry":`, index)
	out = append(out, b...)
	return append(out, '}')
}
