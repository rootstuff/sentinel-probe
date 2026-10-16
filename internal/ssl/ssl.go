// Package ssl reads a server's certificate the way SSLMonitor::probe does:
// one handshake with verification off, the leaf certificate's dates and
// names, and the negotiated protocol and cipher. No verdict is made here;
// the control plane judges the facts on its own clock.
package ssl

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/rootstuff/sentinel-probe/internal/check"
	"github.com/rootstuff/sentinel-probe/internal/guard"
	"github.com/rootstuff/sentinel-probe/internal/port"
)

const HandshakeTimeout = 10 * time.Second

// iso8601 prints UTC as +00:00, as Carbon's toIso8601String does.
const iso8601 = "2006-01-02T15:04:05-07:00"

// Facts is what the control plane's SSLMonitor::judge takes.
type Facts struct {
	Error         *string `json:"error,omitempty"`
	NotBefore     *string `json:"not_before,omitempty"`
	NotAfter      *string `json:"not_after,omitempty"`
	Issuer        *string `json:"issuer,omitempty"`
	Subject       *string `json:"subject,omitempty"`
	TLSProtocol   *string `json:"tls_protocol,omitempty"`
	TLSCipher     *string `json:"tls_cipher,omitempty"`
	TLSCipherBits *int    `json:"tls_cipher_bits,omitempty"`
}

func failed(msg string) Facts { return Facts{Error: &msg} }

func str(s string) *string { return &s }

// Run connects to the URL's host and port (443 by default) and reads the
// certificate it presents. The host is pinned through the guard, so the
// certificate comes from the same address the HTTP check talks to: the
// first IPv4 when there is one. Dialling by name let Go prefer a node's
// global IPv6, and a reset on that path once opened an SSL incident on a
// site whose IPv4 was answering 200 from the same box.
func Run(ctx context.Context, rawURL string, allowPrivate bool) Facts {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return failed("SSL connection failed: invalid URL")
	}
	host := u.Hostname()
	p := u.Port()
	if p == "" {
		p = "443"
	}
	ip, err := guard.Pin(ctx, host, allowPrivate)
	if err == guard.ErrNotPublic {
		return failed("SSL connection failed: cannot monitor private or loopback addresses")
	}
	if err != nil {
		return failed("SSL connection failed: DNS resolution failed")
	}

	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	raw, err := (&net.Dialer{Timeout: HandshakeTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), p))
	if err != nil {
		return failed("SSL connection failed: " + port.Simplify(err))
	}
	// The same hello the HTTP checks present, so the server picks the
	// suite it picks for OpenSSL (AES-256 first), not Go's AES-128.
	conn, err := check.SafeHandshake(ctx, raw, host, true)
	if err != nil {
		raw.Close()
		return failed("SSL connection failed: " + port.Simplify(err))
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return failed("Could not retrieve SSL certificate")
	}
	leaf := state.PeerCertificates[0]

	issuer := "Unknown"
	if len(leaf.Issuer.Organization) > 0 && leaf.Issuer.Organization[0] != "" {
		issuer = leaf.Issuer.Organization[0]
	} else if leaf.Issuer.CommonName != "" {
		issuer = leaf.Issuer.CommonName
	}
	subject := leaf.Subject.CommonName
	if subject == "" {
		subject = host
	}

	f := Facts{
		NotBefore: str(leaf.NotBefore.UTC().Format(iso8601)),
		NotAfter:  str(leaf.NotAfter.UTC().Format(iso8601)),
		Issuer:    str(issuer),
		Subject:   str(subject),
	}
	if name := protocolName(state.Version); name != "" {
		f.TLSProtocol = str(name)
	}
	cipher := tls.CipherSuiteName(state.CipherSuite)
	f.TLSCipher = str(cipher)
	if bits := cipherBits(cipher); bits > 0 {
		f.TLSCipherBits = &bits
	}
	return f
}

// protocolName is the name PHP's stream crypto metadata reports.
func protocolName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1"
	}
	return ""
}

// cipherBits is the symmetric key size the suite name states, as OpenSSL
// reports it to PHP.
func cipherBits(name string) int {
	switch {
	case strings.Contains(name, "_256_"), strings.Contains(name, "CHACHA20"):
		return 256
	case strings.Contains(name, "_128_"):
		return 128
	case strings.Contains(name, "3DES"):
		return 168
	}
	return 0
}
