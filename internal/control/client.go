// Package control talks to the Sentinel control plane on behalf of one
// probe node: a Bearer token and a handful of endpoints, nothing else.
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rootstuff/sentinel-probe/internal/manifest"
	"github.com/rootstuff/sentinel-probe/internal/spool"
)

type Client struct {
	BaseURL   string
	Token     string
	UserAgent string
	HTTP      *http.Client

	// mu guards HTTP, which do replaces after a transport failure, and the
	// ingest fields below.
	mu sync.Mutex

	// ingestURL is where results are posted when the control plane names
	// one on sync (a DNS-only hostname on the origin, so a Cloudflare
	// problem cannot stall uploads, as it did for over an hour on
	// 2026-11-09). Empty: results go to BaseURL. A post that cannot reach
	// it parks it until ingestDownUntil and results go to BaseURL meanwhile.
	ingestURL       string
	ingestDownUntil time.Time
}

// IngestURLHeader is the sync response header naming the ingest URL.
const IngestURLHeader = "X-Sentinel-Ingest-Url"

// ingestCooldown is how long results go through BaseURL after a post to the
// ingest URL fails before it is tried again.
const ingestCooldown = 5 * time.Minute

// Health checks on the one HTTP/2 connection every control-plane request
// shares. Go sends no pings by default, so a connection the network dropped
// without a FIN or RST (a route flap between the node and Cloudflare) stays
// "open" forever and every sync, result post and job wait times out on it
// while a fresh connection would work: ca-central lost 25 minutes of results
// that way on 2026-10-27 until the service was restarted.
const (
	// pingAfterIdle is how long a connection may go without a frame from
	// the control plane before it is pinged.
	pingAfterIdle = 15 * time.Second
	// pingTimeout closes a connection whose ping goes unanswered.
	pingTimeout = 10 * time.Second
	// writeTimeout closes a connection that accepts no bytes for this long.
	writeTimeout = 30 * time.Second
)

func New(baseURL, token, version string) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.HTTP2 = &http.HTTP2Config{
		SendPingTimeout:  pingAfterIdle,
		PingTimeout:      pingTimeout,
		WriteByteTimeout: writeTimeout,
	}

	return &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		Token:     token,
		UserAgent: "sentinel-probe/" + version,
		HTTP:      &http.Client{Timeout: 60 * time.Second, Transport: transport},
	}
}

// do sends one request. A request that fails at the transport (a timeout, a
// reset) retires the whole transport: the next request dials a new
// connection instead of queueing on one that may be dead. Closing idle
// connections is not enough, because the sync, the result post and the job
// wait all hang on the same connection at once, so it is never idle. The old
// connection closes once its requests time out or its ping goes unanswered.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	hc := c.HTTP
	c.mu.Unlock()

	resp, err := hc.Do(req)
	if err != nil {
		c.retire(hc)
	}
	return resp, err
}

// retire swaps in a fresh copy of the transport, once per failed client
// (concurrent failures on the same one swap it a single time).
func (c *Client) retire(failed *http.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()

	old, ok := failed.Transport.(*http.Transport)
	if c.HTTP != failed || !ok {
		return
	}
	c.HTTP = &http.Client{Timeout: failed.Timeout, Transport: old.Clone()}
	old.CloseIdleConnections()
}

// ErrUnauthorized means the token was refused: nothing to retry.
var ErrUnauthorized = errors.New("control plane refused the probe token")

// Sync reports the node's status and returns the manifest, or (nil, nil)
// when the control plane answered 304 to the given ETag.
func (c *Client) Sync(ctx context.Context, etag, version string, status any) (*manifest.Manifest, error) {
	body, _ := json.Marshal(map[string]any{"version": version, "status": status})
	req, err := c.request(ctx, "/api/probe/sync", body)
	if err != nil {
		return nil, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		c.setIngestURL(resp.Header.Get(IngestURLHeader))
	}

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, nil
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	case http.StatusOK:
		var m manifest.Manifest
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&m); err != nil {
			return nil, fmt.Errorf("decode manifest: %w", err)
		}
		m.ETag = resp.Header.Get("ETag")
		return &m, nil
	default:
		return nil, httpError(resp)
	}
}

// Ack is the control plane's per-item verdict on a batch, by index.
type Ack struct {
	Accepted []int `json:"accepted"`
	Skipped  []int `json:"skipped"`
	Failed   []int `json:"failed"`
}

// ErrStorageUnavailable is the 503 the control plane answers when its own
// Redis is unreachable mid-batch: the acked items are final, the rest wait.
var ErrStorageUnavailable = errors.New("control plane storage unavailable")

// ErrTooLarge is nginx's 413 in front of the control plane: the batch as a
// whole was refused, nothing in it was looked at. The poster halves the
// batch and tries again rather than retrying the same request forever
// (Sydney wedged on one such batch for an hour on 2026-10-21).
var ErrTooLarge = errors.New("control plane refused the batch as too large")

// PostResults sends a batch. On 503 the returned Ack still lists what was
// accepted before the control plane gave up, with ErrStorageUnavailable.
func (c *Client) PostResults(ctx context.Context, items []spool.Item) (*Ack, error) {
	type wire struct {
		MonitorID int64           `json:"monitor_id"`
		Type      string          `json:"type,omitempty"`
		CheckedAt string          `json:"checked_at"`
		Result    json.RawMessage `json:"result"`
	}
	results := make([]wire, len(items))
	for i, it := range items {
		results[i] = wire{it.MonitorID, it.Type, it.CheckedAt.UTC().Format(time.RFC3339), it.Result}
	}
	body, _ := json.Marshal(map[string]any{"results": results})
	base, direct := c.resultsBase(time.Now())
	req, err := c.requestTo(ctx, base, "/api/probe/results", body)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		if direct {
			c.parkIngest(time.Now())
			return nil, fmt.Errorf("ingest %s: %w", base, err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	if direct && !ingestAnswered(resp.StatusCode) {
		// Not the control plane answering (a wrong vhost, a dead box after
		// a failover): park the ingest URL and post through BaseURL.
		c.parkIngest(time.Now())
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusServiceUnavailable:
		var ack Ack
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ack); err != nil {
			return nil, fmt.Errorf("decode ack: %w", err)
		}
		if resp.StatusCode == http.StatusServiceUnavailable {
			return &ack, ErrStorageUnavailable
		}
		return &ack, nil
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	case http.StatusRequestEntityTooLarge:
		return nil, ErrTooLarge
	default:
		return nil, httpError(resp)
	}
}

// ResultsVia reports where the next results post goes: "ingest" for the
// ingest URL, "fallback" while it is parked after a failure, or "base"
// when the control plane named none.
func (c *Client) ResultsVia() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.ingestURL == "":
		return "base"
	case time.Now().Before(c.ingestDownUntil):
		return "fallback"
	default:
		return "ingest"
	}
}

// setIngestURL records the ingest URL the control plane named on sync. Only
// an https URL with a host is taken; anything else (or nothing) clears it.
// A changed URL is tried at once, even if the old one was parked.
func (c *Client) setIngestURL(raw string) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if u, err := url.Parse(raw); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		raw = ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if raw != c.ingestURL {
		c.ingestURL = raw
		c.ingestDownUntil = time.Time{}
	}
}

// resultsBase is the base URL for the next results post and whether it is
// the ingest URL.
func (c *Client) resultsBase(now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ingestURL != "" && !now.Before(c.ingestDownUntil) {
		return c.ingestURL, true
	}
	return c.BaseURL, false
}

func (c *Client) parkIngest(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ingestDownUntil = now.Add(ingestCooldown)
}

// ingestAnswered reports whether a status came from the control plane's
// results endpoint (as opposed to something in front of a box that is not
// serving it).
func ingestAnswered(status int) bool {
	switch status {
	case http.StatusOK, http.StatusServiceUnavailable, http.StatusUnauthorized, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return true
	}
	return false
}

func (c *Client) request(ctx context.Context, path string, body []byte) (*http.Request, error) {
	return c.requestTo(ctx, c.BaseURL, path, body)
}

func (c *Client) requestTo(ctx context.Context, base, path string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	return req, nil
}

func httpError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	msg := strings.TrimSpace(string(b))
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return fmt.Errorf("control plane answered %d: %s", resp.StatusCode, msg)
}

// Job is an on-demand check the control plane left for this region: a
// customer's live check, the homepage hero, an agent's check_url.
type Job struct {
	ID string `json:"id"`
	// MonitorID set: run that monitor's own manifest rows now ("check now");
	// the result lands like a scheduled check and nothing is posted here.
	MonitorID    int64  `json:"monitor_id,omitempty"`
	URL          string `json:"url"`
	Timeout      int    `json:"timeout"`
	SourceRegion string `json:"source_region"`
	ExpiresAt    string `json:"expires_at"`
	// Spread: a manual "check now" waits 200 ms per seat before running,
	// so the regions reach the target within about 3 s instead of all at
	// once. A verification burst leaves it unset and runs at once.
	Spread bool `json:"spread,omitempty"`
}

// WaitJob asks for the next on-demand job, blocking on the control plane
// for a few seconds. (nil, nil) means nothing was queued.
func (c *Client) WaitJob(ctx context.Context) (*Job, error) {
	req, err := c.request(ctx, "/api/probe/jobs/wait", []byte("{}"))
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var body struct {
			Job *Job `json:"job"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
			return nil, fmt.Errorf("decode job: %w", err)
		}
		return body.Job, nil
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	default:
		return nil, httpError(resp)
	}
}

// PostJobResult hands the result of an on-demand job back.
func (c *Client) PostJobResult(ctx context.Context, id string, result any) error {
	body, _ := json.Marshal(map[string]any{"result": result})
	req, err := c.request(ctx, "/api/probe/jobs/"+id+"/result", body)
	if err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthorized
	default:
		return httpError(resp)
	}
}
