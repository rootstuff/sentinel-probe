package check

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Why the handshake is done by hand: Akamai's bot manager (and others) score
// the TLS ClientHello. Go's stock crypto/tls has a well-known "automation"
// fingerprint and was refused by www.microsoft.com from a Linode address
// while curl on the same box was let through. The PHP edges have presented
// OpenSSL's handshake under the SentinelBot user agent for a year, so the
// probe presents the same shape: OpenSSL 3 cipher order and extension order,
// minus the groups and suites Go cannot complete (x448, FFDHE, DHE), so a
// server can never pick something the probe then fails on.
func openSSLHello(http1Only bool) *utls.ClientHelloSpec {
	alpn := []string{"h2", "http/1.1"}
	if http1Only {
		alpn = []string{"http/1.1"}
	}
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV, as OpenSSL sends it
		},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0, 1, 2}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP521, utls.CurveP384}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: alpn},
			&utls.UtlsExtendedMasterSecretExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.Ed25519,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
		},
	}
}

// hopConn is one connected, handshaken hop: a RoundTripper bound to a single
// connection, plus the phases measured on the way there.
type hopConn struct {
	rt    http.RoundTripper
	close func()
	ready time.Time
	tcp   time.Duration
	tls   time.Duration
	proto string
}

// connect dials the pinned address, performs the TLS handshake with the
// OpenSSL-shaped ClientHello when the scheme is https, and returns a
// RoundTripper that uses exactly that connection: HTTP/2 when ALPN agreed
// on it, HTTP/1.1 otherwise.
func connect(ctx context.Context, u *url.URL, ip netip.Addr, connectTimeout time.Duration, http1Only bool) (*hopConn, error) {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	dialer := &net.Dialer{Timeout: connectTimeout}
	t0 := time.Now()
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		return nil, err
	}
	hc := &hopConn{tcp: time.Since(t0)}

	if u.Scheme != "https" {
		tr := &http.Transport{DialContext: once(raw)}
		hc.rt, hc.close, hc.ready, hc.proto = tr, tr.CloseIdleConnections, time.Now(), "http/1.1"
		return hc, nil
	}

	uconn := utls.UClient(raw, &utls.Config{ServerName: u.Hostname()}, utls.HelloCustom)
	if err := uconn.ApplyPreset(openSSLHello(http1Only)); err != nil {
		raw.Close()
		return nil, err
	}
	t1 := time.Now()
	if err := uconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	hc.tls = time.Since(t1)
	hc.ready = time.Now()
	hc.proto = uconn.ConnectionState().NegotiatedProtocol

	if hc.proto == "h2" {
		cc, err := (&http2.Transport{}).NewClientConn(uconn)
		if err != nil {
			uconn.Close()
			return nil, err
		}
		hc.rt, hc.close = cc, func() { cc.Close() }
		return hc, nil
	}

	tr := &http.Transport{
		DialTLSContext: once(uconn),
		// The handshake is done and the conn is not a *tls.Conn, so the
		// transport must not try to negotiate HTTP/2 on top of it.
		TLSNextProto: map[string]func(string, *stdTLSConn) http.RoundTripper{},
	}
	hc.rt, hc.close = tr, tr.CloseIdleConnections
	return hc, nil
}

// once hands a pre-dialed connection to a transport exactly one time.
func once(c net.Conn) func(context.Context, string, string) (net.Conn, error) {
	used := false
	return func(context.Context, string, string) (net.Conn, error) {
		if used {
			return nil, errors.New("connection already used")
		}
		used = true
		return c, nil
	}
}
