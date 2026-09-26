// Package tilefetch reads a C2SP tlog-tiles log over HTTP: resource paths, entry bundles, and a
// tlog.TileReader that maps golang.org/x/mod/sumdb/tlog tiles onto tlog-tiles URLs.
//
// Nothing here trusts what it reads. Tiles are authenticated by tlog.TileHashReader against a
// signed tree hash, and entries by comparing their hashes with authenticated tiles (package
// verify). This package only checks shapes: lengths, widths, and the bundle encoding.
package tilefetch

import (
	"fmt"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

// Height is the tile height fixed by tlog-tiles: 2^8 = 256 hashes per full tile.
const Height = 8

// Width is the number of hashes in a full tile and entries in a full bundle.
const Width = 1 << Height

const maxLevel = 63

// encodeIndex writes n as 3-digit groups, all but the last prefixed with "x":
// 1234067 → x001/x234/067.
func encodeIndex(n int64) string {
	groups := []string{fmt.Sprintf("%03d", n%1000)}
	for n >= 1000 {
		n /= 1000
		groups = append(groups, fmt.Sprintf("x%03d", n%1000))
	}
	for i, j := 0, len(groups)-1; i < j; i, j = i+1, j-1 {
		groups[i], groups[j] = groups[j], groups[i]
	}
	return strings.Join(groups, "/")
}

func widthSuffix(w int) string {
	if w == Width {
		return ""
	}
	return fmt.Sprintf(".p/%d", w)
}

// TilePath is the tlog-tiles path of a hash tile, `tile/<L>/<N>[.p/<W>]`. Note that
// tlog.Tile.Path() is the Go checksum database's layout (`tile/<H>/<L>/...`), not this one.
func TilePath(t tlog.Tile) (string, error) {
	if t.H != Height || t.L < 0 || t.L > maxLevel || t.N < 0 || t.W < 1 || t.W > Width {
		return "", fmt.Errorf("tile %+v has no tlog-tiles path", t)
	}
	return fmt.Sprintf("tile/%d/%s%s", t.L, encodeIndex(t.N), widthSuffix(t.W)), nil
}

// BundlePath is the tlog-tiles path of entry bundle n with w entries, `tile/entries/<N>[.p/<W>]`.
// The caller guarantees 0 ≤ n and 1 ≤ w ≤ 256.
func BundlePath(n int64, w int) string {
	return "tile/entries/" + encodeIndex(n) + widthSuffix(w)
}

// BundleWidth is the number of entries bundle n holds in a tree of the given size: 256, or fewer
// for the last bundle. It is 0 if the bundle does not exist at that size.
func BundleWidth(n, size int64) int {
	rest := size - n*Width
	switch {
	case rest <= 0:
		return 0
	case rest >= Width:
		return Width
	default:
		return int(rest)
	}
}
