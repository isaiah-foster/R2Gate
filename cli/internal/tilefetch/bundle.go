package tilefetch

import (
	"encoding/binary"

	"github.com/isaiahfoster/r2notary/cli/internal/verr"
)

// MaxEntrySize is the largest entry a bundle can hold (uint16 length prefix).
const MaxEntrySize = 0xffff

// MaxBundleSize is the largest valid entry bundle: 256 maximum-size entries with their prefixes.
const MaxBundleSize = Width * (2 + MaxEntrySize)

// ParseBundle splits an entry bundle (big-endian uint16 length-prefixed entries) into exactly
// width entries. Anything else, including trailing bytes, is a verification failure.
func ParseBundle(data []byte, width int) ([][]byte, error) {
	entries := make([][]byte, 0, width)
	for len(data) > 0 {
		if len(entries) == width {
			return nil, verr.Failf("entry bundle has more than %d entries", width)
		}
		if len(data) < 2 {
			return nil, verr.Failf("entry bundle ends inside a length prefix")
		}
		n := int(binary.BigEndian.Uint16(data))
		if len(data)-2 < n {
			return nil, verr.Failf("entry bundle ends inside entry %d", len(entries))
		}
		entries = append(entries, data[2:2+n:2+n])
		data = data[2+n:]
	}
	if len(entries) != width {
		return nil, verr.Failf("entry bundle has %d entries, want %d", len(entries), width)
	}
	return entries, nil
}
