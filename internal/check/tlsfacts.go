package check

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
)

// TLSFacts is what a completed handshake says about the certificate and the
// suite: the input to the control plane's SSLMonitor::judge. The HTTP check
// attaches them to every result on an https URL (its first hop, the URL's
// own host), and the SSL sub-check reports them on its own.
type TLSFacts struct {
	NotBefore     *string `json:"not_before,omitempty"`
	NotAfter      *string `json:"not_after,omitempty"`
	Issuer        *string `json:"issuer,omitempty"`
	Subject       *string `json:"subject,omitempty"`
	TLSProtocol   *string `json:"tls_protocol,omitempty"`
	TLSCipher     *string `json:"tls_cipher,omitempty"`
	TLSCipherBits *int    `json:"tls_cipher_bits,omitempty"`
}

// ISO8601 prints UTC as +00:00, as Carbon's toIso8601String does.
const ISO8601 = "2006-01-02T15:04:05-07:00"

// TLSFactsFrom reads the leaf certificate and the negotiated protocol and
// cipher out of a connection state. ok is false when the handshake carried
// no certificate.
func TLSFactsFrom(certs []*x509.Certificate, version, suite uint16, host string) (f TLSFacts, ok bool) {
	if len(certs) == 0 {
		return f, false
	}
	leaf := certs[0]

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

	f = TLSFacts{
		NotBefore: strPtr(leaf.NotBefore.UTC().Format(ISO8601)),
		NotAfter:  strPtr(leaf.NotAfter.UTC().Format(ISO8601)),
		Issuer:    strPtr(issuer),
		Subject:   strPtr(subject),
	}
	if name := protocolName(version); name != "" {
		f.TLSProtocol = strPtr(name)
	}
	cipher := tls.CipherSuiteName(suite)
	f.TLSCipher = strPtr(cipher)
	if bits := cipherBits(cipher); bits > 0 {
		f.TLSCipherBits = &bits
	}
	return f, true
}

func strPtr(s string) *string { return &s }

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
