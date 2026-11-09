package control

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootstuff/sentinel-probe/internal/spool"
)

// The shared HTTP/2 connection is health-checked: a dead one is pinged and
// closed instead of swallowing every request until the service restarts.
func TestNewEnablesHTTP2HealthChecks(t *testing.T) {
	c := New("https://example.test", "spn_test", "test")

	transport, ok := c.HTTP.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.HTTP.Transport)
	}
	if transport.HTTP2 == nil {
		t.Fatal("no HTTP2 config: the connection would never be pinged")
	}
	if transport.HTTP2.SendPingTimeout != pingAfterIdle || transport.HTTP2.PingTimeout != pingTimeout {
		t.Fatalf("ping config = %+v", transport.HTTP2)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatal("HTTP/2 is no longer attempted")
	}
}

// A request that times out retires the transport, so the next sync dials a
// new connection rather than queueing behind a connection that may be dead
// (ca-central, 2026-10-27).
func TestTimedOutRequestRetiresTheConnection(t *testing.T) {
	release := make(chan struct{})
	var dials atomic.Int32

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/probe/jobs/wait" {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"job":null}`))
	}))
	srv.EnableHTTP2 = true
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			dials.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	defer close(release)

	c := New(srv.URL, "spn_test", "test")
	transport := c.HTTP.Transport.(*http.Transport)
	transport.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig

	// The hanging call stands in for a request stuck on a dead connection.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := c.WaitJob(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hanging request: err = %v, want deadline exceeded", err)
	}

	resp, err := c.do(mustRequest(t, c, "/api/probe/sync"))
	if err != nil {
		t.Fatalf("request after the timeout failed: %v", err)
	}
	resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Fatalf("spoke HTTP/%d, want HTTP/2 (the case this guards)", resp.ProtoMajor)
	}
	fresh := c.HTTP.Transport.(*http.Transport)
	if fresh == transport || fresh.HTTP2 == nil || fresh.HTTP2.SendPingTimeout != pingAfterIdle {
		t.Fatal("the replacement transport lost the health-check config")
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("connections dialed = %d, want 2 (the timed-out one must not be reused)", got)
	}
}

func mustRequest(t *testing.T, c *Client, path string) *http.Request {
	t.Helper()
	req, err := c.request(context.Background(), path, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// fakePlane answers sync with an ingest header and records which server got
// each results post.
func fakePlane(t *testing.T, ingest string, hits *[]string, name string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/probe/sync":
			if ingest != "" {
				w.Header().Set(IngestURLHeader, ingest)
			}
			w.WriteHeader(http.StatusNotModified)
		case "/api/probe/results":
			*hits = append(*hits, name)
			w.WriteHeader(status)
			if status == http.StatusOK {
				w.Write([]byte(`{"accepted":[0],"skipped":[],"failed":[]}`))
			}
		}
	}))
}

func oneItem() []spool.Item {
	return []spool.Item{{Seq: 1, MonitorID: 42, CheckedAt: time.Now(), Result: []byte(`{"status":"online"}`)}}
}

func TestResultsGoToTheIngestURLTheSyncNamed(t *testing.T) {
	var hits []string
	ingest := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, "ingest")
		w.Write([]byte(`{"accepted":[0],"skipped":[],"failed":[]}`))
	}))
	defer ingest.Close()
	base := fakePlane(t, ingest.URL+"/", &hits, "base", http.StatusOK)
	defer base.Close()

	c := New(base.URL, "spn_test", "test")
	c.HTTP = ingest.Client() // trusts the test server's certificate; plain http still works
	if _, err := c.Sync(context.Background(), "", "test", nil); err != nil {
		t.Fatal(err)
	}
	if got := c.ResultsVia(); got != "ingest" {
		t.Fatalf("results should go to the ingest URL, via %q", got)
	}
	if _, err := c.PostResults(context.Background(), oneItem()); err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0] != "ingest" {
		t.Fatalf("expected one post to the ingest URL, got %v", hits)
	}
}

func TestUnreachableIngestFallsBackToTheBaseURL(t *testing.T) {
	var hits []string
	dead := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // nothing listens there now

	base := fakePlane(t, deadURL, &hits, "base", http.StatusOK)
	defer base.Close()
	c := New(base.URL, "spn_test", "test")
	if _, err := c.Sync(context.Background(), "", "test", nil); err != nil {
		t.Fatal(err)
	}

	if _, err := c.PostResults(context.Background(), oneItem()); err == nil {
		t.Fatal("the post to a dead ingest URL should fail")
	}
	if got := c.ResultsVia(); got != "fallback" {
		t.Fatalf("a failed ingest post should park it, via %q", got)
	}
	if _, err := c.PostResults(context.Background(), oneItem()); err != nil {
		t.Fatalf("the next post should go through the base URL: %v", err)
	}
	if len(hits) != 1 || hits[0] != "base" {
		t.Fatalf("expected the retry on the base URL, got %v", hits)
	}

	// The cooldown passes and the ingest URL is tried again.
	c.mu.Lock()
	c.ingestDownUntil = time.Now().Add(-time.Second)
	c.mu.Unlock()
	if got := c.ResultsVia(); got != "ingest" {
		t.Fatalf("after the cooldown the ingest URL should be tried again, via %q", got)
	}
}

func TestIngestAnsweringSomethingElseIsParked(t *testing.T) {
	var hits []string
	wrong := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // a vhost that does not serve the probe API
	}))
	defer wrong.Close()
	base := fakePlane(t, wrong.URL, &hits, "base", http.StatusOK)
	defer base.Close()
	c := New(base.URL, "spn_test", "test")
	c.HTTP = wrong.Client()
	if _, err := c.Sync(context.Background(), "", "test", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PostResults(context.Background(), oneItem()); err == nil {
		t.Fatal("a 404 from the ingest URL should fail the post")
	}
	if got := c.ResultsVia(); got != "fallback" {
		t.Fatalf("a 404 should park the ingest URL, via %q", got)
	}
}

func TestOnlyAnHTTPSIngestURLIsTaken(t *testing.T) {
	c := New("https://control.example", "spn_test", "test")
	for _, raw := range []string{"", "http://ingest.example", "not a url", "https://", "https://user:pw@ingest.example"} {
		c.setIngestURL(raw)
		if got := c.ResultsVia(); got != "base" {
			t.Errorf("%q should not be taken, via %q", raw, got)
		}
	}
	c.setIngestURL("https://ingest.example/")
	if base, direct := c.resultsBase(time.Now()); !direct || base != "https://ingest.example" {
		t.Fatalf("an https URL should be taken without its trailing slash, got %q %v", base, direct)
	}
	c.setIngestURL("")
	if got := c.ResultsVia(); got != "base" {
		t.Fatalf("a sync without the header should clear it, via %q", got)
	}
}
