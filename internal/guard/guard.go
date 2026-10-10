// Package guard mirrors app/Services/SsrfGuard.php: a target is monitored
// only when every address its host resolves to is publicly routable, and the
// connection is then pinned to one vetted address so a second resolution
// cannot land on an internal one.
package guard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
)

var (
	// ErrUnresolvable is the wording MonitorCheckService stores when a host has no address.
	ErrUnresolvable = errors.New("DNS resolution failed")
	// ErrNotPublic is the wording stored when any resolved address is private or reserved.
	ErrNotPublic = errors.New("Target host is not publicly routable")
)

var blockedHosts = map[string]bool{"localhost": true}

// Blocked ranges. PHP's FILTER_FLAG_NO_PRIV_RANGE | NO_RES_RANGE plus the
// ranges SsrfGuard adds by hand (CGNAT 100.64/10, benchmarking 198.18/15).
// Multicast (224/4, ff00::/8) is blocked here and not in PHP: a deliberate
// superset, nothing monitorable lives there.
var blockedV4 = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
)

var blockedV6 = mustPrefixes("::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// IsPublicIP reports whether an address is neither private nor reserved. The
// IPv6 forms that carry an IPv4 address (mapped, compatible, NAT64, 6to4,
// Teredo) are judged by the address they embed, as SsrfGuard does.
func IsPublicIP(ip netip.Addr) bool {
	if ip.Is4() {
		for _, p := range blockedV4 {
			if p.Contains(ip) {
				return false
			}
		}
		return true
	}

	if embedded, ok := embeddedV4(ip); ok {
		return IsPublicIP(embedded)
	}

	for _, p := range blockedV6 {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func embeddedV4(ip netip.Addr) (netip.Addr, bool) {
	b := ip.As16()
	zero12 := true
	for _, x := range b[:12] {
		if x != 0 {
			zero12 = false
			break
		}
	}

	switch {
	case ip.Is4In6(): // ::ffff:a.b.c.d
		return ip.Unmap(), true
	case zero12: // ::a.b.c.d (IPv4-compatible); also catches :: and ::1 as 0.0.0.x
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case b[0] == 0 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && allZero(b[4:12]): // 64:ff9b::/96 NAT64
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case b[0] == 0x20 && b[1] == 0x02: // 2002:a.b.c.d::/48 6to4
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	case b[0] == 0x20 && b[1] == 0x01 && b[2] == 0 && b[3] == 0: // 2001::/32 Teredo, client v4 is the last 32 bits inverted
		return netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}), true
	}
	return netip.Addr{}, false
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// Resolver is the lookup Pin uses; tests swap it, as SsrfGuard::resolveUsing does.
var Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Pin resolves a host, rejects it unless every address is public, and returns
// the address to dial: the first IPv4 when there is one (checks pin v4 today),
// else the first IPv6. AllowPrivate is for local benchmarking only.
func Pin(ctx context.Context, host string, allowPrivate bool) (netip.Addr, error) {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" || blockedHosts[host] || strings.HasSuffix(host, ".localhost") {
		if allowPrivate && host != "" {
			return pinLocal(ctx, host)
		}
		return netip.Addr{}, ErrNotPublic
	}

	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip.Unmap()}
	} else {
		found, err := Resolver(ctx, host)
		if err != nil || len(found) == 0 {
			return netip.Addr{}, ErrUnresolvable
		}
		ips = found
	}

	var v4, v6 *netip.Addr
	for i := range ips {
		ip := ips[i].Unmap()
		if !allowPrivate && !IsPublicIP(ip) {
			return netip.Addr{}, ErrNotPublic
		}
		if ip.Is4() && v4 == nil {
			v4 = &ip
		} else if ip.Is6() && v6 == nil {
			v6 = &ip
		}
	}
	if v4 != nil {
		return *v4, nil
	}
	return *v6, nil
}

func pinLocal(ctx context.Context, host string) (netip.Addr, error) {
	if host == "localhost" {
		return netip.MustParseAddr("127.0.0.1"), nil
	}
	found, err := Resolver(ctx, host)
	if err != nil || len(found) == 0 {
		return netip.Addr{}, ErrUnresolvable
	}
	return found[0].Unmap(), nil
}
