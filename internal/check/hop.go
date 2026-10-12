package check

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Why the handshake is done by hand, and which hello is the default.
//
// Bot managers score the TLS ClientHello per address. Measured from a Linode
// address at a monitor's cadence (one request every few seconds, the
// London grid of 2026-10-10):
//
//   - safeHello (OpenSSL-shaped, only what Go completes): 200 on every site,
//     Akamai (www.microsoft.com) and five Cloudflare-fronted customers.
//   - curlHello (Ubuntu curl 8.5 / OpenSSL 3.0 byte for byte): 200 on Akamai,
//     403 on the Cloudflare sites, exactly like real curl from the same box.
//     Cloudflare verifies SentinelBot by the published IP list, so from an
//     unlisted address a curl handshake claiming to be the bot is challenged,
//     while an unfamiliar handshake passes on reputation alone.
//   - Go's stock hello also passed at cadence; its earlier refusals were
//     per-(address, fingerprint) penalties earned by burst benchmarks, which
//     is why they followed whichever hello had been bursting.
//
// So safeHello is the default: it passes everywhere measured, and it never
// offers a suite, group or signature scheme Go cannot finish. curlHello
// stays for diagnosis (-hello curl), with a one-shot fallback to safeHello
// when a server picks DHE, x448 or FFDHE from it. Whatever the hello, a new
// probe address must be on the published /bot IP list before it checks
// Cloudflare-fronted customers.
func curlHello(http1Only bool) *utls.ClientHelloSpec {
	alpn := []string{"h2", "http/1.1"}
	if http1Only {
		alpn = []string{"http/1.1"}
	}
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			4866, 4867, 4865, // TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256
			49196, 49200, 159, // ECDHE-ECDSA-AES256-GCM, ECDHE-RSA-AES256-GCM, DHE-RSA-AES256-GCM
			52393, 52392, 52394, // ECDHE-ECDSA-CHACHA20, ECDHE-RSA-CHACHA20, DHE-RSA-CHACHA20
			49195, 49199, 158, // ECDHE-ECDSA-AES128-GCM, ECDHE-RSA-AES128-GCM, DHE-RSA-AES128-GCM
			49188, 49192, 107, // ECDHE-ECDSA-AES256-SHA384, ECDHE-RSA-AES256-SHA384, DHE-RSA-AES256-SHA256
			49187, 49191, 103, // ECDHE-ECDSA-AES128-SHA256, ECDHE-RSA-AES128-SHA256, DHE-RSA-AES128-SHA256
			49162, 49172, 57, // ECDHE-ECDSA-AES256-SHA, ECDHE-RSA-AES256-SHA, DHE-RSA-AES256-SHA
			49161, 49171, 51, // ECDHE-ECDSA-AES128-SHA, ECDHE-RSA-AES128-SHA, DHE-RSA-AES128-SHA
			157, 156, 61, 60, 53, 47, // AES256-GCM, AES128-GCM, AES256-SHA256, AES128-SHA256, AES256-SHA, AES128-SHA
			255, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
		},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0, 1, 2}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519, utls.CurveP256, 30, utls.CurveP521, utls.CurveP384, // x448 = 30
				256, 257, 258, 259, 260, // ffdhe2048..ffdhe8192
			}},
			&utls.ALPNExtension{AlpnProtocols: alpn},
			&utls.GenericExtension{Id: 22}, // encrypt_then_mac
			&utls.UtlsExtendedMasterSecretExtension{},
			&utls.GenericExtension{Id: 49}, // post_handshake_auth
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				// Ubuntu 24.04 curl/OpenSSL 3.0, in its order, read off the echo service.
				utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP521AndSHA512,
				utls.Ed25519, 0x0808, // ed448
				0x0809, 0x080a, 0x080b, // rsa_pss_pss_sha256/384/512
				utls.PSSWithSHA256, utls.PSSWithSHA384, utls.PSSWithSHA512, // rsa_pss_rsae_sha256/384/512
				utls.PKCS1WithSHA256, utls.PKCS1WithSHA384, utls.PKCS1WithSHA512,
				0x0303, 0x0301, 0x0302, // ecdsa_sha224, rsa_sha224, dsa_sha224
				0x0402, 0x0502, 0x0602, // dsa_sha256, dsa_sha384, dsa_sha512
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}

// safeHello is the default hello: OpenSSL's shape, only what Go can complete.
func safeHello(http1Only bool) *utls.ClientHelloSpec {
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
			0x00ff,
		},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0, 1, 2}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP521, utls.CurveP384}},
			&utls.ALPNExtension{AlpnProtocols: alpn},
			&utls.UtlsExtendedMasterSecretExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP521AndSHA512, utls.Ed25519,
				utls.PSSWithSHA256, utls.PSSWithSHA384, utls.PSSWithSHA512,
				utls.PKCS1WithSHA256, utls.PKCS1WithSHA384, utls.PKCS1WithSHA512,
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
	conn  net.Conn
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
func connect(ctx context.Context, u *url.URL, ip netip.Addr, connectTimeout time.Duration, http1Only bool, hello string) (*hopConn, error) {
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
	hc := &hopConn{conn: raw, tcp: time.Since(t0)}

	if u.Scheme != "https" {
		hc.close, hc.ready, hc.proto = func() { raw.Close() }, time.Now(), "http/1.1"
		return hc, nil
	}

	t1 := time.Now()
	var uconn *utls.UConn
	var err2 error
	switch hello {
	case "safe":
		uconn, err2 = handshake(ctx, raw, u.Hostname(), safeHello(http1Only))
	case "go":
		uconn, err2 = handshakeStock(ctx, raw, u.Hostname(), http1Only)
	case "curl":
		uconn, err2 = handshake(ctx, raw, u.Hostname(), curlHello(http1Only))
	default:
		uconn, err2 = handshake(ctx, raw, u.Hostname(), safeHello(http1Only))
	}
	err = err2
	if err != nil && hello == "curl" && retryWithSafeHello(err) {
		raw.Close()
		raw, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err != nil {
			return hc, err
		}
		hc.conn = raw
		uconn, err = handshake(ctx, raw, u.Hostname(), safeHello(http1Only))
	}
	hc.tls = time.Since(t1)
	if err != nil {
		raw.Close()
		return hc, err
	}
	hc.ready = time.Now()
	hc.proto = uconn.ConnectionState().NegotiatedProtocol
	hc.conn = uconn

	if hc.proto == "h2" {
		cc, err := (&http2.Transport{}).NewClientConn(uconn)
		if err != nil {
			uconn.Close()
			return nil, err
		}
		hc.rt, hc.close = cc, func() { cc.Close() }
		return hc, nil
	}

	// HTTP/1.1: the request is written by hand (see h1.go), no transport.
	hc.close = func() { uconn.Close() }
	return hc, nil
}

// SafeHandshake completes a TLS handshake on raw with the safe hello (the
// OpenSSL-shaped one every HTTP check presents, so a server negotiates the
// same suite it does with the PHP edge). With skipVerify the certificate is
// not validated: the SSL sub-check reads expired and mismatched
// certificates on purpose.
func SafeHandshake(ctx context.Context, raw net.Conn, serverName string, skipVerify bool) (*utls.UConn, error) {
	uconn := utls.UClient(raw, &utls.Config{ServerName: serverName, InsecureSkipVerify: skipVerify}, utls.HelloCustom)
	if err := uconn.ApplyPreset(safeHello(true)); err != nil {
		return nil, err
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uconn, nil
}

func handshake(ctx context.Context, raw net.Conn, serverName string, spec *utls.ClientHelloSpec) (*utls.UConn, error) {
	uconn := utls.UClient(raw, &utls.Config{ServerName: serverName}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, err
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uconn, nil
}

// retryWithSafeHello: a handshake that failed for a reason other than the
// certificate, a timeout or the peer going away is most likely the server
// choosing a suite, group or signature scheme the curl-shaped hello offers
// but Go cannot complete.
func retryWithSafeHello(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{"certificate", "x509", "connection reset", "eof", "broken pipe"} {
		if strings.Contains(msg, s) {
			return false
		}
	}
	return true
}

// handshakeStock is Go's own crypto/tls hello, kept for A/B diagnosis only.
func handshakeStock(ctx context.Context, raw net.Conn, serverName string, http1Only bool) (*utls.UConn, error) {
	alpn := []string{"h2", "http/1.1"}
	if http1Only {
		alpn = []string{"http/1.1"}
	}
	uconn := utls.UClient(raw, &utls.Config{ServerName: serverName, NextProtos: alpn}, utls.HelloGolang)
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uconn, nil
}
