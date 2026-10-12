package whois

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const rdapExample = `{"events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},{"eventAction":"expiration","eventDate":"2027-08-13T04:00:00Z"}],
"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RESERVED-Internet Assigned Numbers Authority"]]]}],
"nameservers":[{"ldhName":"A.IANA-SERVERS.NET"},{"ldhName":"B.IANA-SERVERS.NET"}],"status":["client delete prohibited","client transfer prohibited"]}`

func TestRDAPFactsMatchThePHPReader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domain/example.com" || r.Header.Get("Accept") != "application/rdap+json" {
			w.WriteHeader(404)
			return
		}
		w.Write([]byte(rdapExample))
	}))
	defer srv.Close()
	c := &Client{RDAPBase: srv.URL, HTTP: srv.Client(), WhoisRoot: "127.0.0.1:1"}

	f := c.Lookup(context.Background(), "Example.COM.")
	if !f.Success || f.Source != "rdap" {
		t.Fatalf("facts: %+v", f)
	}
	if *f.ExpirationDate != "2027-08-13T04:00:00Z" || *f.CreationDate != "1995-08-14T04:00:00Z" {
		t.Errorf("dates: %s %s", *f.ExpirationDate, *f.CreationDate)
	}
	if f.Registrar != "RESERVED-Internet Assigned Numbers Authority" {
		t.Errorf("registrar %q", f.Registrar)
	}
	if len(f.NameServers) != 2 || f.NameServers[0] != "a.iana-servers.net" {
		t.Errorf("name servers %v", f.NameServers)
	}
	if len(f.States) != 2 {
		t.Errorf("states %v", f.States)
	}

	// Unknown to RDAP and WHOIS unreachable: a failure the control plane
	// records as such, never a change.
	g := c.Lookup(context.Background(), "nope.invalid")
	if g.Success || g.Error == nil {
		t.Errorf("unknown domain: %+v", g)
	}
}

func TestWhoisParseReadsRegistryAndRegistrarAnswers(t *testing.T) {
	verisign := `   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.registrar.example
   Registrar: Example Registrar, LLC
   Updated Date: 2026-08-14T07:01:31Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2027-08-13T04:00:00Z
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
>>> Last update of whois database: 2026-10-12T12:00:00Z <<<`
	f, next := parse("example.com", verisign)
	if next != "whois.registrar.example" {
		t.Errorf("referral %q", next)
	}
	if f.ExpirationDate == nil || *f.ExpirationDate != "2027-08-13T04:00:00Z" {
		t.Errorf("expiry %v", f.ExpirationDate)
	}
	if f.Registrar != "Example Registrar, LLC" || len(f.NameServers) != 2 || f.NameServers[1] != "b.iana-servers.net" {
		t.Errorf("facts %+v", f)
	}
	if len(f.States) != 2 || f.States[0] != "clientDeleteProhibited" {
		t.Errorf("states %v", f.States)
	}

	// A ccTLD spelling.
	nominet := "    Domain name:\n        example.co.uk\n\n    Registrar:\n        Some Registrar Ltd [Tag = SOME]\n\n    Expiry date:  13-Aug-2027\n    Name servers:\n        ns1.example.co.uk\n"
	g, _ := parse("example.co.uk", nominet)
	if g.ExpirationDate == nil || *g.ExpirationDate != "2027-08-13T00:00:00Z" {
		t.Errorf("nominet expiry %v", g.ExpirationDate)
	}
}

func TestNormalizeDateSpellings(t *testing.T) {
	cases := map[string]string{
		"2027-08-13T04:00:00Z":         "2027-08-13T04:00:00Z",
		"2027-08-13 04:00:00":          "2027-08-13T04:00:00Z",
		"13-Aug-2027":                  "2027-08-13T00:00:00Z",
		"2027.08.13":                   "2027-08-13T00:00:00Z",
		"2027-08-13T04:00:00.000+0200": "2027-08-13T02:00:00Z",
		"2027-08-13 04:00:00 (UTC+3)":  "2027-08-13T04:00:00Z",
		"not a date":                   "",
	}
	for in, want := range cases {
		if got := normalizeDate(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}
