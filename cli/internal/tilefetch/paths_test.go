package tilefetch

import (
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// Examples from C2SP tlog-tiles.
func TestTilePath(t *testing.T) {
	cases := []struct {
		tile tlog.Tile
		want string
	}{
		{tlog.Tile{H: 8, L: 0, N: 0, W: 256}, "tile/0/000"},
		{tlog.Tile{H: 8, L: 0, N: 1234067, W: 256}, "tile/0/x001/x234/067"},
		{tlog.Tile{H: 8, L: 0, N: 1234067, W: 8}, "tile/0/x001/x234/067.p/8"},
		{tlog.Tile{H: 8, L: 1, N: 1, W: 17}, "tile/1/001.p/17"},
		{tlog.Tile{H: 8, L: 2, N: 0, W: 1}, "tile/2/000.p/1"},
		{tlog.Tile{H: 8, L: 0, N: 999, W: 256}, "tile/0/999"},
		{tlog.Tile{H: 8, L: 0, N: 1000, W: 256}, "tile/0/x001/000"},
		{tlog.Tile{H: 8, L: 3, N: 1000000, W: 255}, "tile/3/x001/x000/000.p/255"},
	}
	for _, c := range cases {
		got, err := TilePath(c.tile)
		if err != nil || got != c.want {
			t.Errorf("TilePath(%+v) = %q, %v; want %q", c.tile, got, err, c.want)
		}
	}
}

func TestBundlePath(t *testing.T) {
	if got := BundlePath(1234067, 256); got != "tile/entries/x001/x234/067" {
		t.Errorf("full bundle: %q", got)
	}
	if got := BundlePath(273, 112); got != "tile/entries/273.p/112" {
		t.Errorf("partial bundle: %q", got)
	}
}

// Go's own tile paths (tile/<H>/<L>/<N>) differ from tlog-tiles but encode N the same way, so they
// give an independent check of the index encoding over many values.
func TestTilePathAgreesWithGoEncoding(t *testing.T) {
	for _, n := range []int64{0, 1, 9, 10, 99, 100, 999, 1000, 1001, 65535, 999999, 1000000, 123456789, 1 << 40} {
		for _, w := range []int{1, 100, 255, 256} {
			tile := tlog.Tile{H: 8, L: 2, N: n, W: w}
			got, err := TilePath(tile)
			if err != nil {
				t.Fatal(err)
			}
			want := "tile/" + strings.TrimPrefix(tile.Path(), "tile/8/")
			if got != want {
				t.Errorf("N=%d W=%d: %q, want %q", n, w, got, want)
			}
		}
	}
}

func TestTilePathRejectsWhatTlogTilesCannotName(t *testing.T) {
	for _, tile := range []tlog.Tile{
		{H: 4, L: 0, N: 0, W: 16},   // only height 8 exists
		{H: 8, L: -1, N: 0, W: 256}, // Go's data tiles are entry bundles here
		{H: 8, L: 0, N: -1, W: 256},
		{H: 8, L: 0, N: 0, W: 0},
		{H: 8, L: 0, N: 0, W: 257},
		{H: 8, L: 64, N: 0, W: 1},
	} {
		if p, err := TilePath(tile); err == nil {
			t.Errorf("TilePath(%+v) = %q, want error", tile, p)
		}
	}
}
