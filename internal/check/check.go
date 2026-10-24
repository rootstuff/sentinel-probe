// Package check performs one HTTP monitor check with the semantics of
// app/Services/MonitorCheckService.php + PinnedHttpClient.php: the same
// request headers, the same timeout split, up to three vetted redirect hops
// with a throwaway cookie jar, IPv4-first pinning, the same timing phases
// and the same status and error wording.
package check

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rootstuff/sentinel-probe/internal/guard"
)

const (
	UserAgent    = "Mozilla/5.0 (compatible; SentinelBot/1.0; +https://sentinel.rootstuff.io/bot)"
	MaxRedirects = 3
	// MaxBodyBytes caps how much of a response is read. PHP reads the whole
	// body; the cap is an explicit safety the Laravel side never had.
	MaxBodyBytes = 10 << 20
	// CaptureBodyBytes caps what travels back to the control plane.
	CaptureBodyBytes = 2 << 20
	// DiagnosisBodyBytes is how much of a failed page travels back with
	// its headers for every monitor, so the control plane can say what the
	// failure is (a WordPress fatal, a parked domain) without the body
	// being asked for.
	DiagnosisBodyBytes = 64 << 10
)

// Options describes one check. Zero values take the monitor defaults.
type Options struct {
	URL             string
	Method          string
	Region          string
	Timeout         time.Duration
	FollowRedirects *bool
	AcceptedCodes   []string
	Headers         map[string]string
	Body            string
	// AllowPrivate disables the public-address guard. Local benchmarking only.
	AllowPrivate bool
	// HTTP2 opts in to HTTP/2. Off by default: a check is one request on one
	// connection, so multiplexing buys nothing, and Akamai's bot manager
	// fingerprints the h2 SETTINGS/window/header-order of Go's x/net client
	// (www.microsoft.com returned 403 on h2 and 200 on HTTP/1.1 from the
	// same box, after the TLS handshake had already been made to pass).
	// curl's h2 shape is not reproducible without forking x/net.
	HTTP2 bool
	// BareHeaders sends only the User-Agent, to rule the header set out.
	BareHeaders bool
	// BodySink, when set, receives the final response body (up to MaxBodyBytes).
	BodySink io.Writer
	// CaptureBody keeps the final response's headers and up to
	// CaptureBodyBytes of its decoded body on the Result, for monitors the
	// control plane judges itself (payment envelopes, JSON assertions).
	CaptureBody bool
	// Hello picks the ClientHello: "safe" (default: OpenSSL-shaped, only what
	// Go completes), "curl" (curl/OpenSSL byte for byte) or "go" (stock
	// crypto/tls). See hop.go for why safe is the default.
	Hello string
}

// Result is the row the Laravel side would store, field names included.
type Result struct {
	Status       string  `json:"status"`
	ResponseTime int     `json:"response_time"`
	StatusCode   *int    `json:"status_code"`
	Error        *string `json:"error"`
	FinalURL     string  `json:"final_url"`
	DNSMs        int     `json:"dns_ms"`
	TCPMs        int     `json:"tcp_ms"`
	TLSMs        int     `json:"tls_ms"`
	TTFBMs       int     `json:"ttfb_ms"`
	PrimaryIP    string  `json:"primary_ip,omitempty"`
	Hops         int     `json:"hops"`
	BodyBytes    int64   `json:"body_bytes"`
	Proto        string  `json:"proto,omitempty"`
	// Set with Options.CaptureBody, and on any final response whose status
	// was not accepted (then the body is the first DiagnosisBodyBytes).
	Headers       map[string][]string `json:"headers,omitempty"`
	BodyB64       string              `json:"body_b64,omitempty"`
	BodyTruncated bool                `json:"body_truncated,omitempty"`
}

type phases struct {
	tcp, tls, ttfb time.Duration
	proto          string
}

func (o Options) withDefaults() Options {
	if o.Method == "" {
		o.Method = "GET"
	}
	o.Method = strings.ToUpper(o.Method)
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	if o.FollowRedirects == nil {
		t := true
		o.FollowRedirects = &t
	}
	if len(o.AcceptedCodes) == 0 {
		o.AcceptedCodes = []string{"2xx", "3xx"}
	}
	if o.Region == "" {
		o.Region = "local"
	}
	return o
}

// ConnectTimeout mirrors the PHP split: a third of the budget, at least 5s,
// never more than the budget.
func ConnectTimeout(timeout time.Duration) time.Duration {
	third := time.Duration(math.Ceil(timeout.Seconds()/3)) * time.Second
	if third < 5*time.Second {
		third = 5 * time.Second
	}
	if third > timeout {
		third = timeout
	}
	return third
}

// Run performs the check. It never panics and never returns an error: a
// failure is a Result with Status "offline" and Error set, as in PHP.
func Run(ctx context.Context, o Options) Result {
	o = o.withDefaults()
	start := time.Now()
	res := Result{FinalURL: o.URL}
	fail := func(msg string) Result {
		res.Status = "offline"
		res.Error = &msg
		res.ResponseTime = int(time.Since(start).Milliseconds())
		return res
	}

	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	jar, _ := cookiejar.New(nil)
	headers := orderedHeaders(o)
	method, body, current := o.Method, o.Body, o.URL
	connectTimeout := ConnectTimeout(o.Timeout)

	for hops := 0; ; hops++ {
		u, err := url.Parse(current)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fail("Invalid URL")
		}

		dnsStart := time.Now()
		ip, err := guard.Pin(ctx, u.Hostname(), o.AllowPrivate)
		res.DNSMs = int(time.Since(dnsStart).Milliseconds())
		if err != nil {
			return fail(err.Error())
		}
		res.PrimaryIP = ip.String()

		remaining := o.Timeout - time.Since(start)
		if hops > 0 && remaining <= 500*time.Millisecond {
			return fail("Redirect chain exceeded the request timeout")
		}
		hopTimeout := o.Timeout
		if hops > 0 {
			hopTimeout = max(time.Second, remaining)
		}

		resp, ph, closeHop, hopCancel, err := doHop(ctx, hopTimeout, connectTimeout, method, u, ip, headers, body, jar, !o.HTTP2, o.Hello)
		res.TCPMs, res.TLSMs, res.TTFBMs = int(ph.tcp.Milliseconds()), int(ph.tls.Milliseconds()), int(ph.ttfb.Milliseconds())
		if ph.proto != "" {
			res.Proto = ph.proto
		}
		if err != nil {
			closeHop()
			hopCancel()
			return fail(simplify(err))
		}

		var sink io.Writer = io.Discard
		if o.BodySink != nil {
			sink = o.BodySink
		}
		capture := &limitedBuffer{limit: DiagnosisBodyBytes}
		if o.CaptureBody {
			capture = &limitedBuffer{limit: CaptureBodyBytes}
		}
		sink = io.MultiWriter(sink, capture)
		decoded, decErr := decodeBody(resp)
		var n int64
		readErr := decErr
		if decErr == nil {
			n, readErr = io.Copy(sink, io.LimitReader(decoded, MaxBodyBytes))
		}
		resp.Body.Close()
		closeHop()
		hopCancel()
		res.BodyBytes = n
		if readErr != nil {
			return fail(simplify(readErr))
		}

		code := resp.StatusCode
		res.StatusCode = &code
		res.Hops = hops
		location := resp.Header.Get("Location")

		if !*o.FollowRedirects || !isRedirect(code) || location == "" {
			if o.CaptureBody || !statusAccepted(code, o.AcceptedCodes) {
				res.Headers = resp.Header.Clone()
				res.BodyB64 = base64.StdEncoding.EncodeToString(capture.buf)
				res.BodyTruncated = capture.truncated
			}
			res.FinalURL = current
			res.ResponseTime = int(time.Since(start).Milliseconds())
			if statusAccepted(code, o.AcceptedCodes) {
				res.Status = "online"
			} else {
				res.Status = "offline"
				msg := fmt.Sprintf("HTTP %d", code)
				res.Error = &msg
			}
			return res
		}

		if hops >= MaxRedirects {
			return fail(fmt.Sprintf("Will not follow more than %d redirects", MaxRedirects))
		}

		next, err := u.Parse(location)
		if err != nil {
			return fail("Invalid redirect location")
		}

		// 301/302/303 turn a body-carrying request into GET (HEAD stays
		// HEAD); 307/308 keep method and body.
		if (code == 301 || code == 302 || code == 303) && method != "HEAD" {
			method, body = "GET", ""
		}

		// Configured credentials belong to the original host only.
		if !strings.EqualFold(next.Hostname(), u.Hostname()) {
			headers = dropHeader(dropHeader(headers, "Authorization"), "Cookie")
		}

		current = next.String()
	}
}

func doHop(ctx context.Context, hopTimeout, connectTimeout time.Duration, method string, u *url.URL, ip netip.Addr, headers []header, body string, jar http.CookieJar, http1Only bool, hello string) (*http.Response, phases, func(), context.CancelFunc, error) {
	hctx, cancel := context.WithTimeout(ctx, hopTimeout)
	noop := func() {}

	hc, err := connect(hctx, u, ip, connectTimeout, http1Only, hello)
	if err != nil {
		ph := phases{}
		if hc != nil {
			ph.tcp, ph.tls = hc.tcp, hc.tls
		}
		return nil, ph, noop, cancel, err
	}
	ph := phases{tcp: hc.tcp, tls: hc.tls, proto: hc.proto}

	if hc.proto != "h2" {
		resp, firstByte, err := roundTripH1(hctx, hc.conn, method, u, headers, body, jar)
		if !firstByte.IsZero() {
			ph.ttfb = max(0, firstByte.Sub(hc.ready))
		}
		if resp != nil {
			ph.proto = resp.Proto
		}
		return resp, ph, hc.close, cancel, err
	}

	var firstByte time.Time
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}

	client := &http.Client{
		Transport: hc.rt,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var reader io.Reader
	if body != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(hctx, trace), method, u.String(), reader)
	if err != nil {
		return nil, ph, hc.close, cancel, err
	}
	for _, h := range headers {
		req.Header.Set(h.k, h.v)
	}
	if reader != nil && json.Valid([]byte(body)) {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)

	// Phase-isolated TTFB: from "connection fully ready" to the first
	// response byte, so the phases add up instead of double-counting.
	if !firstByte.IsZero() {
		ph.ttfb = max(0, firstByte.Sub(hc.ready))
	}
	if resp != nil && resp.Proto != "" {
		ph.proto = resp.Proto
	}

	return resp, ph, hc.close, cancel, err
}

func isRedirect(code int) bool {
	return code >= 300 && code < 400
}

// statusAccepted mirrors determineStatus/matchesStatusCode: "2xx" style
// prefixes or exact codes.
func statusAccepted(code int, patterns []string) bool {
	s := strconv.Itoa(code)
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if strings.HasSuffix(p, "xx") && len(p) == 3 {
			if strings.HasPrefix(s, p[:1]) {
				return true
			}
		} else if p == s {
			return true
		}
	}
	return false
}

// simplify mirrors simplifyError: the five canonical phrases, else the first
// 100 characters of the message with Go's "Get \"url\": " wrapper removed.
func simplify(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		err = uerr.Err
	}
	msg := err.Error()
	// net.OpError prefixes "read tcp 10.0.0.2:51234->1.2.3.4:443:", which
	// leaks the probe's own address and buries the cause; keep the cause.
	// The dial op is remembered before the prefix goes: it is the only
	// thing that tells a connect timeout from a slow response once the
	// message is just "i/o timeout".
	var operr *net.OpError
	dialing := false
	if errors.As(err, &operr) && operr.Err != nil {
		dialing = operr.Op == "dial"
		msg = operr.Err.Error()
	}

	var certErr interface{ Error() string }
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	var netErr net.Error

	switch {
	case errors.As(err, &unknownCA), errors.As(err, &hostErr), errors.As(err, &invalidErr),
		strings.Contains(msg, "x509:"), strings.Contains(strings.ToLower(msg), "certificate"):
		return "SSL certificate error"
	case strings.Contains(msg, "connection refused"):
		return "Connection refused"
	case strings.Contains(msg, "connection reset"):
		return "Connection reset by peer"
	case strings.Contains(msg, "no such host"):
		return "DNS resolution failed"
	case errors.As(err, &netErr) && netErr.Timeout() && (dialing || strings.Contains(msg, "dial tcp")):
		return "Connection timeout"
	case strings.Contains(msg, "TLS handshake timeout"):
		return "Connection timeout"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "Request timeout"
	}
	_ = certErr
	if len(msg) > 100 {
		msg = msg[:100]
	}
	return msg
}

// limitedBuffer keeps the first `limit` bytes and remembers whether more came.
type limitedBuffer struct {
	buf       []byte
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	room := b.limit - len(b.buf)
	if room > 0 {
		if len(p) > room {
			b.buf = append(b.buf, p[:room]...)
			b.truncated = true
		} else {
			b.buf = append(b.buf, p...)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}
