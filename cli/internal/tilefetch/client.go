package tilefetch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/isaiahfoster/r2notary/cli/internal/verr"
)

// MaxCheckpointSize bounds a checkpoint download. Real ones are a few hundred bytes.
const MaxCheckpointSize = 1 << 20

// FetchError means a resource could not be read (network failure or a non-200 status). It is not
// a verification failure: nothing wrong was received.
type FetchError struct {
	URL    string
	Status int // 0 for transport errors
	Err    error
}

func (e *FetchError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("GET %s: HTTP %d", e.URL, e.Status)
	}
	return fmt.Sprintf("GET %s: %v", e.URL, e.Err)
}

func (e *FetchError) Unwrap() error { return e.Err }

// Client fetches resources under a log's URL prefix, e.g. https://host/log/name.
type Client struct {
	base  string
	token string
	http  *http.Client

	// Tiles that tlog.TileHashReader has authenticated. Every use re-authenticates them against
	// the tree in hand, so this only saves downloads. Full level-0 tiles are not kept: a scan reads
	// each one once, and keeping them would grow with the log.
	mu    sync.Mutex
	tiles map[tlog.Tile][]byte
}

// NewClient returns a client for the log at base (http or https). A non-empty token is sent as
// `Authorization: Bearer <token>` (private logs). Go's HTTP client drops it on redirects to
// another host.
func NewClient(base, token string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("log URL %q must be an absolute http(s) URL", base)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("log URL %q must not have a query or fragment", base)
	}
	return &Client{
		base:  strings.TrimRight(base, "/"),
		token: token,
		http:  &http.Client{Timeout: 60 * time.Second},
		tiles: make(map[tlog.Tile][]byte),
	}, nil
}

// Get returns the resource at path (relative to the log prefix). A body longer than max bytes is
// a verification failure: no valid resource is that large.
func (c *Client) Get(ctx context.Context, path string, max int64) ([]byte, error) {
	return c.get(ctx, c.base+"/"+path, max)
}

// GetURL fetches an absolute URL with the client's token (used for the lookup API).
func (c *Client) GetURL(ctx context.Context, rawURL string, max int64) ([]byte, error) {
	return c.get(ctx, rawURL, max)
}

func (c *Client) get(ctx context.Context, u string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, &FetchError{URL: u, Err: err}
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	// No Accept-Encoding is set, so the transport asks for gzip and decompresses transparently
	// (entry bundles are served gzip-encoded). The size limit below applies after decompression.
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &FetchError{URL: u, Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &FetchError{URL: u, Status: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, &FetchError{URL: u, Err: err}
	}
	if int64(len(data)) > max {
		return nil, verr.Failf("GET %s: response is larger than %d bytes", u, max)
	}
	return data, nil
}

// Bundle fetches entry bundle n with width w and splits it into its entries.
func (c *Client) Bundle(ctx context.Context, n int64, w int) ([][]byte, error) {
	data, err := c.Get(ctx, BundlePath(n, w), MaxBundleSize)
	if err != nil {
		return nil, err
	}
	entries, err := ParseBundle(data, w)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", BundlePath(n, w), err)
	}
	return entries, nil
}

// TileReader returns a tlog.TileReader backed by this client. tlog's interface has no context,
// so the reader carries one.
func (c *Client) TileReader(ctx context.Context) tlog.TileReader {
	return &tileReader{ctx: ctx, c: c}
}

type tileReader struct {
	ctx context.Context
	c   *Client
}

func (r *tileReader) Height() int { return Height }

func (r *tileReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	data := make([][]byte, len(tiles))
	for i, t := range tiles {
		r.c.mu.Lock()
		cached, ok := r.c.tiles[t]
		r.c.mu.Unlock()
		if ok {
			data[i] = cached
			continue
		}
		path, err := TilePath(t)
		if err != nil {
			return nil, err
		}
		d, err := r.c.Get(r.ctx, path, int64(t.W*tlog.HashSize))
		if err != nil {
			return nil, err
		}
		if len(d) != t.W*tlog.HashSize {
			return nil, verr.Failf("%s is %d bytes, want %d", path, len(d), t.W*tlog.HashSize)
		}
		data[i] = d
	}
	return data, nil
}

func (r *tileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	for i, t := range tiles {
		if t.L == 0 && t.W == Width {
			continue
		}
		r.c.tiles[t] = data[i]
	}
}
