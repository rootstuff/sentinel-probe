package port

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/rootstuff/sentinel-probe/internal/guard"
)

func TestRefusesPrivateAndInvalid(t *testing.T) {
	ctx := t.Context()
	if r := Run(ctx, "127.0.0.1", 80, false); *r.Error != "Cannot monitor private or loopback addresses" {
		t.Fatalf("loopback: %+v", r)
	}
	if r := Run(ctx, "not a host", 80, false); *r.Error != "Invalid host on monitor" {
		t.Fatalf("invalid: %+v", r)
	}
	if r := Run(ctx, "example.com", 70000, false); *r.Error != "Invalid port on monitor" {
		t.Fatalf("port: %+v", r)
	}
}

func TestSimplify(t *testing.T) {
	cases := map[string]string{
		"dial tcp 1.2.3.4:22: connect: connection refused": "Connection refused",
		"dial tcp 1.2.3.4:22: i/o timeout":                 "Connection timed out",
		"dial tcp: lookup nope.invalid: no such host":      "DNS resolution failed",
		"dial tcp 1.2.3.4:22: connect: no route to host":   "Network unreachable",
	}
	for in, want := range cases {
		if got := Simplify(&net.OpError{Err: errString(in)}); got != want {
			t.Errorf("Simplify(%q) = %q, want %q", in, got, want)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// A dual-stack name is connected at its IPv4, as the HTTP check does, even
// when the resolver lists IPv6 first. The listener is on 127.0.0.1 only,
// so a connect to ::1 would be refused.
func TestConnectsToThePinnedIPv4OfADualStackName(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	orig := guard.Resolver
	guard.Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
		if host != "dual.test" {
			return orig(ctx, host)
		}
		return []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	defer func() { guard.Resolver = orig }()

	port := ln.Addr().(*net.TCPAddr).Port
	if r := Run(context.Background(), "dual.test", port, true); r.Status != "online" {
		t.Errorf("status %s, error %v", r.Status, r.Error)
	}
	if r := Run(context.Background(), "dual.test", port, false); *r.Error != "Cannot monitor private or loopback addresses" {
		t.Errorf("private: %v", r.Error)
	}
	if r := Run(context.Background(), "does-not-resolve.invalid", 443, false); *r.Error != "DNS resolution failed" {
		t.Errorf("unresolvable: %v", r.Error)
	}
}
