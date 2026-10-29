package ssl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/rootstuff/sentinel-probe/internal/check"
	"github.com/rootstuff/sentinel-probe/internal/guard"
)

func TestReadsLeafCertificateFacts(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	f := Run(context.Background(), srv.URL, true)
	if f.Error != nil {
		t.Fatalf("error: %s", *f.Error)
	}
	want := srv.Certificate().NotAfter.UTC().Format(check.ISO8601)
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

// A dual-stack name is dialled at its IPv4, as the HTTP check does, even
// when the resolver lists IPv6 first. The server only listens on
// 127.0.0.1, so a dial to ::1 would be refused.
func TestDialsThePinnedIPv4OfADualStackName(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	orig := guard.Resolver
	guard.Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
		if host != "dual.test" {
			return orig(ctx, host)
		}
		return []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	defer func() { guard.Resolver = orig }()

	u, _ := url.Parse(srv.URL)
	f := Run(context.Background(), "https://dual.test:"+u.Port(), true)
	if f.Error != nil {
		t.Fatalf("error: %s", *f.Error)
	}
	if f.NotAfter == nil {
		t.Error("expected certificate facts")
	}

	if f := Run(context.Background(), "https://dual.test:"+u.Port(), false); f.Error == nil || *f.Error != "SSL connection failed: cannot monitor private or loopback addresses" {
		t.Errorf("private: %v", f.Error)
	}
	if f := Run(context.Background(), "https://does-not-resolve.invalid/", true); f.Error == nil || *f.Error != "SSL connection failed: DNS resolution failed" {
		t.Errorf("unresolvable: %v", f.Error)
	}
}
