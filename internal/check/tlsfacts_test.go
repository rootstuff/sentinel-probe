package check

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

// An https check carries the certificate its own host presented: the
// control plane judges SSL from this instead of a separate handshake.
func TestHTTPSResultCarriesCertificateFacts(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	trustTestServer(t, srv)

	r := run(t, Options{URL: srv.URL})
	if r.Status != "online" || r.Error != nil {
		t.Fatalf("unexpected result %+v", r)
	}
	want := srv.Certificate().NotAfter.UTC().Format(ISO8601)
	if r.NotAfter == nil || *r.NotAfter != want {
		t.Errorf("not_after %v, want %s", r.NotAfter, want)
	}
	if r.NotBefore == nil || r.Issuer == nil || r.Subject == nil {
		t.Errorf("incomplete facts %+v", r.TLSFacts)
	}
	if r.TLSProtocol == nil || *r.TLSProtocol != "TLSv1.3" {
		t.Errorf("protocol %v", r.TLSProtocol)
	}
	if r.TLSCipherBits == nil || (*r.TLSCipherBits != 128 && *r.TLSCipherBits != 256) {
		t.Errorf("bits %v", r.TLSCipherBits)
	}
}

// The facts describe the URL's own host, the first hop, even when the
// check follows a redirect to another server.
func TestFactsComeFromTheFirstHopNotTheRedirectTarget(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(target.Close)
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(first.Close)
	trustTestServer(t, first, target)

	r := run(t, Options{URL: first.URL})
	if r.Status != "online" || r.Hops != 1 {
		t.Fatalf("unexpected result %+v", r)
	}
	want := first.Certificate().NotAfter.UTC().Format(ISO8601)
	if r.NotAfter == nil || *r.NotAfter != want {
		t.Errorf("not_after %v, want first hop's %s", r.NotAfter, want)
	}
}

// Plain http has no certificate, and a failed handshake leaves none.
func TestNoFactsWithoutACompletedHandshake(t *testing.T) {
	plain := serve(t, func(w http.ResponseWriter, r *http.Request) {})
	if r := run(t, Options{URL: plain.URL}); r.NotAfter != nil || r.TLSProtocol != nil {
		t.Errorf("plain http carried facts: %+v", r.TLSFacts)
	}

	// Untrusted certificate: the handshake fails verification.
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(untrusted.Close)
	r := run(t, Options{URL: untrusted.URL})
	if r.Status != "offline" || r.NotAfter != nil {
		t.Errorf("failed handshake should carry no facts: %+v", r)
	}
}

func trustTestServer(t *testing.T, servers ...*httptest.Server) {
	t.Helper()
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	prev := rootCAs
	rootCAs = pool
	t.Cleanup(func() { rootCAs = prev })
}
