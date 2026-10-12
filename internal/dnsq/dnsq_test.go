package dnsq

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFormatMatchesSpatie(t *testing.T) {
	cases := map[string]Record{
		"example.com. 300 IN A 203.0.113.10":                                {"type": "A", "value": "203.0.113.10", "ttl": 300},
		"example.com. 300 IN AAAA 2606:4700:0:0:0:0:6810:84e5":              {"type": "AAAA", "value": "2606:4700::6810:84e5", "ttl": 300},
		"www.example.com. 60 IN CNAME Example.COM.":                         {"type": "CNAME", "value": "example.com", "ttl": 60},
		"example.com. 3600 IN MX 10 Mail.Example.com.":                      {"type": "MX", "value": "mail.example.com", "priority": 10, "ttl": 3600},
		"example.com. 3600 IN NS ns1.example.com.":                          {"type": "NS", "value": "ns1.example.com", "ttl": 3600},
		`example.com. 300 IN TXT "v=spf1 include:" "_spf.example.com -all"`: {"type": "TXT", "value": "v=spf1 include:_spf.example.com -all", "ttl": 300},
		"example.com. 0 IN MX 0 .":                                          {"type": "MX", "value": "", "priority": 0, "ttl": 0},
		"example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 2026101201 7200 3600 1209600 300": {
			"type": "SOA", "primary": "ns1.example.com", "admin": "hostmaster.example.com",
			"serial": 2026101201, "refresh": 7200, "retry": 3600, "expire": 1209600, "minimum": 300, "ttl": 3600,
		},
	}
	for line, want := range cases {
		got := Format(rr(t, line))
		if len(got) != len(want) {
			t.Errorf("%s: got %v want %v", line, got, want)
			continue
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s: %s = %v (%T), want %v (%T)", line, k, got[k], got[k], v, v)
			}
		}
	}
}

// A tiny authoritative server so the full query path runs without the
// network.
func fakeServer(t *testing.T, zone map[uint16][]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		for _, line := range zone[req.Question[0].Qtype] {
			m.Answer = append(m.Answer, rr(t, line))
		}
		// A subdomain's SOA comes back in the authority section.
		if req.Question[0].Qtype == dns.TypeSOA {
			m.Ns = append(m.Ns, rr(t, "example.com. 1800 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300"))
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestRunWithQueriesEveryTypeAndFillsEmptyOnes(t *testing.T) {
	addr := fakeServer(t, map[uint16][]string{
		dns.TypeA:  {"example.com. 300 IN A 203.0.113.10", "example.com. 300 IN A 203.0.113.11"},
		dns.TypeMX: {"example.com. 3600 IN MX 10 mail.example.com."},
	})
	res := RunWith(context.Background(), "Example.com.", []string{addr})
	if res.Error != nil {
		t.Fatalf("error: %s", *res.Error)
	}
	if len(res.Failures) != 0 {
		t.Errorf("failures: %v", res.Failures)
	}
	if len(res.Records) != len(Types) {
		t.Errorf("every type must be present: %v", Sorted(res.Records))
	}
	if len(res.Records["A"]) != 2 || len(res.Records["MX"]) != 1 || len(res.Records["TXT"]) != 0 || len(res.Records["SOA"]) != 1 {
		t.Errorf("records: %v", res.Records)
	}
}

func TestUnreachableResolverIsAnErrorNotAChange(t *testing.T) {
	res := RunWith(context.Background(), "example.com", []string{"127.0.0.1:1"})
	if res.Error == nil || *res.Error != "DNS query failed for multiple record types: A, AAAA, NS" {
		t.Errorf("error %v", res.Error)
	}
	if len(res.Records) != 0 {
		t.Errorf("no records should be reported with the error: %v", res.Records)
	}
}
