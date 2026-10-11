package port

import (
	"net"
	"testing"
)

func TestRefusesPrivateAndInvalid(t *testing.T) {
	ctx := t.Context()
	if r := Run(ctx, "127.0.0.1", 80); *r.Error != "Cannot monitor private or loopback addresses" {
		t.Fatalf("loopback: %+v", r)
	}
	if r := Run(ctx, "not a host", 80); *r.Error != "Invalid host on monitor" {
		t.Fatalf("invalid: %+v", r)
	}
	if r := Run(ctx, "example.com", 70000); *r.Error != "Invalid port on monitor" {
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
		if got := simplify(&net.OpError{Err: errString(in)}); got != want {
			t.Errorf("simplify(%q) = %q, want %q", in, got, want)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }
