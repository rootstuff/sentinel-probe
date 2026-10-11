// Package target mirrors the host rules PingService and PortService apply
// before touching the network: how a host is taken from the stored target,
// what counts as a valid host, and which hosts are refused.
package target

import (
	"context"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/rootstuff/sentinel-probe/internal/guard"
)

var hostname = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// ExtractHost is PingService/PortService::extractHost: the URL's host, or
// the raw value when it is a bare host (no "/" and no ":").
func ExtractHost(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Hostname()
	}
	if !strings.Contains(raw, "/") && !strings.Contains(raw, ":") {
		return raw
	}
	return ""
}

// IsValidHost is isValidHost: an IP literal or an RFC 1123-ish name.
func IsValidHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	return hostname.MatchString(host)
}

// Public reports whether the host may be probed: a literal must be public,
// a name must resolve to only public addresses. Unresolvable is refused
// for ping (the ping itself would say so) and allowed through for port
// (PortService lets the connect report the DNS failure), hence the flag.
func Public(ctx context.Context, host string, allowUnresolvable bool) bool {
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "127.0.0.1" || lower == "::1" || lower == "0.0.0.0" {
		return false
	}
	_, err := guard.Pin(ctx, host, false)
	if err == nil {
		return true
	}
	return allowUnresolvable && err == guard.ErrUnresolvable
}
