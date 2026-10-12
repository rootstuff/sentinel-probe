package ssl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadsLeafCertificateFacts(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	f := Run(context.Background(), srv.URL, true)
	if f.Error != nil {
		t.Fatalf("error: %s", *f.Error)
	}
	want := srv.Certificate().NotAfter.UTC().Format(iso8601)
	if f.NotAfter == nil || *f.NotAfter != want {
		t.Errorf("not_after %v, want %s", f.NotAfter, want)
	}
	if f.TLSProtocol == nil || *f.TLSProtocol != "TLSv1.3" {
		t.Errorf("protocol %v", f.TLSProtocol)
	}
	if f.TLSCipherBits == nil || (*f.TLSCipherBits != 128 && *f.TLSCipherBits != 256) {
		t.Errorf("bits %v", f.TLSCipherBits)
	}
	if f.Issuer == nil || *f.Issuer == "" {
		t.Errorf("issuer %v", f.Issuer)
	}
}

func TestRefusesPrivateTargetsAndReportsFailures(t *testing.T) {
	if f := Run(context.Background(), "https://127.0.0.1:1", false); f.Error == nil || *f.Error != "SSL connection failed: cannot monitor private or loopback addresses" {
		t.Errorf("private: %v", f.Error)
	}
	if f := Run(context.Background(), "https://127.0.0.1:1", true); f.Error == nil || *f.Error != "SSL connection failed: Connection refused" {
		t.Errorf("refused: %v", f.Error)
	}
	if f := Run(context.Background(), "nonsense", true); f.Error == nil {
		t.Error("invalid URL should fail")
	}
}
