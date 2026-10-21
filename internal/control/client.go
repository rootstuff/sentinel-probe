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
	"strings"
	"time"

	"github.com/rootstuff/sentinel-probe/internal/manifest"
	"github.com/rootstuff/sentinel-probe/internal/spool"
)

type Client struct {
	BaseURL   string
	Token     string
	UserAgent string
	HTTP      *http.Client
}

func New(baseURL, token, version string) *Client {
	return &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		Token:     token,
		UserAgent: "sentinel-probe/" + version,
		HTTP:      &http.Client{Timeout: 60 * time.Second},
	}
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
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
	req, err := c.request(ctx, "/api/probe/results", body)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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

func (c *Client) request(ctx context.Context, path string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
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
}

// WaitJob asks for the next on-demand job, blocking on the control plane
// for a few seconds. (nil, nil) means nothing was queued.
func (c *Client) WaitJob(ctx context.Context) (*Job, error) {
	req, err := c.request(ctx, "/api/probe/jobs/wait", []byte("{}"))
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
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
	resp, err := c.HTTP.Do(req)
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
