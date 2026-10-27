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
