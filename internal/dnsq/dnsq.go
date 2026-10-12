// Package dnsq resolves a host the way DNSCheckService::queryDNSRecords
// does through spatie/dns and dig: one query per record type against the
// box's resolver, each answer formatted exactly as the PHP side stores it
// (hostnames lowercased with the trailing dot removed, TXT strings joined,
// the SOA fields by name), so a snapshot written from a probe region
// compares clean against one written from an edge.
package dnsq

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	QueryTimeout = 5 * time.Second
	resolvConf   = "/etc/resolv.conf"
)

// Types is the order DNSCheckService queries them.
var Types = []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"}

var qtypes = map[string]uint16{
	"A": dns.TypeA, "AAAA": dns.TypeAAAA, "CNAME": dns.TypeCNAME, "MX": dns.TypeMX,
	"NS": dns.TypeNS, "TXT": dns.TypeTXT, "SOA": dns.TypeSOA,
}

// Record is one formatted answer: the keys DNSCheckService::formatRecords
// writes for the type.
type Record = map[string]any

// Result is what DNSMonitor::replay takes.
type Result struct {
	Records  map[string][]Record `json:"records"`
	Failures map[string]string   `json:"failures"`
	// Error is set when the critical types could not be queried; the
	// control plane records a dns_error instead of comparing.
	Error *string `json:"error,omitempty"`
}

// Run resolves the host through the box's configured nameservers.
func Run(ctx context.Context, host string) Result {
	return RunWith(ctx, host, Servers())
}

// Servers is the resolver list from /etc/resolv.conf, with public
// fallbacks when the file has none.
func Servers() []string {
	var out []string
	if cfg, err := dns.ClientConfigFromFile(resolvConf); err == nil {
		for _, s := range cfg.Servers {
			out = append(out, net.JoinHostPort(s, cfg.Port))
		}
	}
	if len(out) == 0 {
		out = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	return out
}

// RunWith resolves the host through the given nameservers (host:port).
func RunWith(ctx context.Context, host string, servers []string) Result {
	res := Result{Records: map[string][]Record{}, Failures: map[string]string{}}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		msg := "Invalid URL - cannot extract hostname"
		res.Error = &msg
		return res
	}

	for _, typ := range Types {
		answers, err := query(ctx, host, qtypes[typ], servers)
		if err != nil {
			res.Failures[typ] = err.Error()
			continue
		}
		records := []Record{}
		for _, rr := range answers {
			if r := Format(rr); r != nil {
				records = append(records, r)
			}
		}
		res.Records[typ] = records
	}

	// As queryDNSRecords: two or more of the critical types failing is a
	// resolver problem, not a zone change.
	var critical []string
	for _, typ := range []string{"A", "AAAA", "NS"} {
		if _, failed := res.Failures[typ]; failed {
			critical = append(critical, typ)
		}
	}
	if len(critical) >= 2 {
		msg := "DNS query failed for multiple record types: " + strings.Join(critical, ", ")
		res.Error = &msg
		res.Records = map[string][]Record{}
		return res
	}
	for _, typ := range Types {
		if _, ok := res.Records[typ]; !ok {
			res.Records[typ] = []Record{}
		}
	}
	return res
}

// query asks each server in turn and keeps the first answer. A DNS status
// such as NXDOMAIN or SERVFAIL is an answer with no records, as dig exits
// zero on those; only no reply at all is a failure.
func query(ctx context.Context, host string, qtype uint16, servers []string) ([]dns.RR, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.RecursionDesired = true

	var last error
	for _, server := range servers {
		for _, network := range []string{"udp", "tcp"} {
			c := &dns.Client{Net: network, Timeout: QueryTimeout}
			in, _, err := c.ExchangeContext(ctx, msg, server)
			if err != nil {
				last = err
				break // next server
			}
			if in.Truncated && network == "udp" {
				continue // same server over TCP
			}
			// spatie runs dig with +answer +authority and keeps the lines
			// of the asked type, so a subdomain's SOA (served in the
			// authority section) counts like an apex's.
			var answers []dns.RR
			for _, section := range [][]dns.RR{in.Answer, in.Ns} {
				for _, rr := range section {
					if rr.Header().Rrtype == qtype {
						answers = append(answers, rr)
					}
				}
			}
			return answers, nil
		}
	}
	if last == nil {
		last = errors.New("no nameservers configured")
	}
	return nil, fmt.Errorf("no reply from nameservers: %s", last.Error())
}

// Format is DNSCheckService::formatRecords for one answer, or nil for a
// type it does not store.
func Format(rr dns.RR) Record {
	ttl := int(rr.Header().Ttl)
	switch v := rr.(type) {
	case *dns.A:
		return Record{"type": "A", "value": v.A.String(), "ttl": ttl}
	case *dns.AAAA:
		return Record{"type": "AAAA", "value": v.AAAA.String(), "ttl": ttl}
	case *dns.CNAME:
		return Record{"type": "CNAME", "value": domain(v.Target), "ttl": ttl}
	case *dns.MX:
		return Record{"type": "MX", "value": domain(v.Mx), "priority": int(v.Preference), "ttl": ttl}
	case *dns.NS:
		return Record{"type": "NS", "value": domain(v.Ns), "ttl": ttl}
	case *dns.TXT:
		// dig prints the strings quoted and spatie joins them with nothing
		// between.
		return Record{"type": "TXT", "value": strings.Join(v.Txt, ""), "ttl": ttl}
	case *dns.SOA:
		return Record{
			"type": "SOA", "primary": domain(v.Ns), "admin": domain(v.Mbox),
			"serial": int(v.Serial), "refresh": int(v.Refresh), "retry": int(v.Retry),
			"expire": int(v.Expire), "minimum": int(v.Minttl), "ttl": ttl,
		}
	}
	return nil
}

// domain is spatie's prepareDomain: the trailing dot removed and the name
// lowercased; the root label alone becomes the empty string.
func domain(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Sorted returns the type names in query order (for stable output).
func Sorted(r map[string][]Record) []string {
	keys := make([]string, 0, len(r))
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
