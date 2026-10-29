// Package ssl reads a server's certificate the way SSLMonitor::probe does:
// one handshake with verification off, the leaf certificate's dates and
// names, and the negotiated protocol and cipher. No verdict is made here;
// the control plane judges the facts on its own clock.
package ssl

import (
	"context"
	"net"
	"net/url"
	"time"

	"github.com/rootstuff/sentinel-probe/internal/check"
	"github.com/rootstuff/sentinel-probe/internal/guard"
	"github.com/rootstuff/sentinel-probe/internal/port"
)

const HandshakeTimeout = 10 * time.Second

// Facts is what the control plane's SSLMonitor::judge takes: the shared
// certificate facts, or the error that stopped the handshake.
type Facts struct {
	Error *string `json:"error,omitempty"`
	check.TLSFacts
}

func failed(msg string) Facts { return Facts{Error: &msg} }

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
	facts, ok := check.TLSFactsFrom(state.PeerCertificates, state.Version, state.CipherSuite, host)
	if !ok {
		return failed("Could not retrieve SSL certificate")
	}
	return Facts{TLSFacts: facts}
}
