package guard

import (
	"net/netip"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	cases := map[string]bool{
		"93.184.216.34":    true,
		"8.8.8.8":          true,
		"10.0.0.5":         false,
		"172.16.0.1":       false,
		"192.168.1.1":      false,
		"127.0.0.1":        false,
		"169.254.169.254":  false,
		"100.64.0.1":       false,
		"198.18.0.1":       false,
		"224.0.0.1":        false,
		"2606:4700::1111":  true,
		"::1":              false,
		"::":               false,
		"fe80::1":          false,
		"fd00::1":          false,
		"::ffff:10.0.0.1":  false,
		"::ffff:8.8.8.8":   true,
		"64:ff9b::a00:1":   false, // NAT64 of 10.0.0.1
		"2002:0a00:0001::": false, // 6to4 of 10.0.0.1
		"2002:0808:0808::": true,  // 6to4 of 8.8.8.8
	}
	for in, want := range cases {
		if got := IsPublicIP(netip.MustParseAddr(in)); got != want {
			t.Errorf("IsPublicIP(%s) = %v, want %v", in, got, want)
		}
	}
}
