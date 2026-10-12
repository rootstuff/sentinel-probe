// Package whois looks up a domain's registration the way
// DomainMonitoringService does: the registry's RDAP record (structured,
// authoritative, reached through the rdap.org redirector) with port-43
// WHOIS as the fallback for the registries that still only speak that.
// The control plane counts the days and raises the incident.
package whois

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	QueryTimeout = 10 * time.Second
	// RDAPBase is rdap.org, which redirects to the TLD's own RDAP server.
	RDAPBase = "https://rdap.org"
)

// Facts is what DomainMonitor::replay takes.
type Facts struct {
	Success        bool     `json:"success"`
	Domain         string   `json:"domain"`
	Source         string   `json:"source,omitempty"`
	Registrar      string   `json:"registrar,omitempty"`
	CreationDate   *string  `json:"creation_date"`
	ExpirationDate *string  `json:"expiration_date"`
	States         []string `json:"states"`
	NameServers    []string `json:"name_servers"`
	Error          *string  `json:"error,omitempty"`
}

// Lookup resolves a registrable domain's facts.
func Lookup(ctx context.Context, domain string) Facts {
	return (&Client{RDAPBase: RDAPBase, HTTP: &http.Client{Timeout: QueryTimeout}}).Lookup(ctx, domain)
}

// Client is Lookup with its endpoints injectable (tests).
type Client struct {
	RDAPBase string
	HTTP     *http.Client
	// WhoisRoot is the IANA root whois server; tests point it elsewhere.
	WhoisRoot string
}

func (c *Client) Lookup(ctx context.Context, domain string) Facts {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	if domain == "" || !strings.Contains(domain, ".") {
		return failed(domain, "Could not retrieve domain information. The domain might not exist or be invalid.")
	}

	if f, ok := c.rdap(ctx, domain); ok && f.ExpirationDate != nil {
		return f
	}
	if f, ok := c.whois(ctx, domain); ok && f.ExpirationDate != nil {
		return f
	}
	return failed(domain, "Could not retrieve domain information. The domain might not exist or be invalid.")
}

func failed(domain, msg string) Facts {
	return Facts{Domain: domain, States: []string{}, NameServers: []string{}, Error: &msg}
}

func str(s string) *string { return &s }

// ---- RDAP (the same fields DomainMonitoringService::rdapLookup reads)

func (c *Client) rdap(ctx context.Context, domain string) (Facts, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.RDAPBase, "/")+"/domain/"+domain, nil)
	if err != nil {
		return Facts{}, false
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Facts{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Facts{}, false
	}
	var data struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles      []string        `json:"roles"`
			VcardArray json.RawMessage `json:"vcardArray"`
		} `json:"entities"`
		Nameservers []struct {
			LDHName string `json:"ldhName"`
		} `json:"nameservers"`
		Status []string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&data); err != nil {
		return Facts{}, false
	}

	f := Facts{Success: true, Domain: domain, Source: "rdap", Registrar: "Unknown", States: []string{}, NameServers: []string{}}
	for _, e := range data.Events {
		switch strings.ToLower(e.Action) {
		case "expiration":
			f.ExpirationDate = str(normalizeDate(e.Date))
		case "registration":
			f.CreationDate = str(normalizeDate(e.Date))
		}
	}
	for _, e := range data.Entities {
		if !contains(e.Roles, "registrar") {
			continue
		}
		if name := vcardFN(e.VcardArray); name != "" {
			f.Registrar = name
			break
		}
	}
	for _, ns := range data.Nameservers {
		if ns.LDHName != "" {
			f.NameServers = append(f.NameServers, strings.ToLower(ns.LDHName))
		}
	}
	f.States = append(f.States, data.Status...)
	return f, true
}

// vcardFN reads the "fn" property of a jCard: ["vcard", [["fn", {}, "text", "Name"], ...]].
func vcardFN(raw json.RawMessage) string {
	var card []json.RawMessage
	if json.Unmarshal(raw, &card) != nil || len(card) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if json.Unmarshal(card[1], &props) != nil {
		return ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var key, value string
		if json.Unmarshal(p[0], &key) == nil && key == "fn" && json.Unmarshal(p[3], &value) == nil {
			return value
		}
	}
	return ""
}

// ---- WHOIS (port 43, following the registry's referral to the registrar)

var whoisKeys = map[string][]string{
	"expiration": {"registry expiry date", "registrar registration expiration date", "expiration date", "expiry date", "expires on", "expires", "domain expires", "domain expiration date", "expiration time", "expire date", "expiry", "record expires on", "paid-till", "renewal date", "expire", "valid until", "registry expiry"},
	"creation":   {"creation date", "created on", "created", "registered on", "registration date", "registered", "domain record activated", "registration time", "record created on"},
	"registrar":  {"registrar", "sponsoring registrar"},
	"nameserver": {"name server", "nserver", "nameserver"},
	"status":     {"domain status", "status"},
	"referral":   {"registrar whois server", "whois server", "refer"},
}

func (c *Client) whois(ctx context.Context, domain string) (Facts, bool) {
	root := c.WhoisRoot
	if root == "" {
		root = "whois.iana.org:43"
	}
	// Root -> TLD registry -> registrar, keeping the richest answer.
	server := root
	var best Facts
	found := false
	for hop := 0; hop < 3 && server != ""; hop++ {
		text, err := query(ctx, server, domain)
		if err != nil {
			break
		}
		f, next := parse(domain, text)
		if f.ExpirationDate != nil && (!found || best.ExpirationDate == nil) {
			best, found = f, true
		} else if !found && (f.Registrar != "Unknown" || len(f.NameServers) > 0) {
			best, found = f, true
		}
		if next == "" || strings.EqualFold(next, strings.TrimSuffix(server, ":43")) {
			break
		}
		server = next
		if !strings.Contains(server, ":") {
			server += ":43"
		}
	}
	return best, found
}

func query(ctx context.Context, server, domain string) (string, error) {
	d := net.Dialer{Timeout: QueryTimeout}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(QueryTimeout))
	if _, err := fmt.Fprintf(conn, "%s\r\n", domain); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil && len(b) == 0 {
		return "", err
	}
	return string(b), nil
}

// parse reads "key: value" lines, case-insensitively, and returns the
// facts plus the referral server if the answer names one.
func parse(domain, text string) (Facts, string) {
	f := Facts{Success: true, Domain: domain, Source: "whois", Registrar: "Unknown", States: []string{}, NameServers: []string{}}
	referral := ""
	seenNS := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">>>") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		switch {
		case matches(key, whoisKeys["expiration"]):
			if f.ExpirationDate == nil {
				if d := normalizeDate(value); d != "" {
					f.ExpirationDate = str(d)
				}
			}
		case matches(key, whoisKeys["creation"]):
			if f.CreationDate == nil {
				if d := normalizeDate(value); d != "" {
					f.CreationDate = str(d)
				}
			}
		case matches(key, whoisKeys["referral"]):
			if referral == "" {
				referral = strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(value), "whois://"), "rwhois://")
			}
		case matches(key, whoisKeys["registrar"]):
			if f.Registrar == "Unknown" {
				f.Registrar = value
			}
		case matches(key, whoisKeys["nameserver"]):
			ns := strings.ToLower(strings.Fields(value)[0])
			ns = strings.TrimSuffix(ns, ".")
			if ns != "" && !seenNS[ns] {
				seenNS[ns] = true
				f.NameServers = append(f.NameServers, ns)
			}
		case matches(key, whoisKeys["status"]):
			// "clientTransferProhibited https://icann.org/epp#..." -> the code.
			f.States = append(f.States, strings.Fields(value)[0])
		}
	}
	return f, referral
}

func matches(key string, names []string) bool {
	for _, n := range names {
		if key == n {
			return true
		}
	}
	return false
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

var dateLayouts = []string{
	time.RFC3339, time.RFC3339Nano,
	"2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05.000Z0700",
	"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02 15:04:05 MST", "2006-01-02 15:04:05-07",
	"2006-01-02", "2006.01.02", "02-Jan-2006", "02-Jan-2006 15:04:05 MST", "2006/01/02", "02.01.2006", "January 2 2006", "2 Jan 2006",
	"Mon Jan 2 15:04:05 MST 2006", "2006-01-02T15:04:05.0Z",
}

var trailingTZ = regexp.MustCompile(`\s*\([^)]*\)$`)

// normalizeDate turns the many WHOIS date spellings into RFC 3339 UTC; the
// control plane parses that with Carbon.
func normalizeDate(v string) string {
	v = strings.TrimSpace(trailingTZ.ReplaceAllString(v, ""))
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ""
}
