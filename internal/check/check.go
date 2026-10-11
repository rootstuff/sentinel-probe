// Package check performs one HTTP monitor check with the semantics of
// app/Services/MonitorCheckService.php + PinnedHttpClient.php: the same
// request headers, the same timeout split, up to three vetted redirect hops
// with a throwaway cookie jar, IPv4-first pinning, the same timing phases
// and the same status and error wording.
package check

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
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

type stdTLSConn = stdtls.Conn

const (
	UserAgent    = "Mozilla/5.0 (compatible; SentinelBot/1.0; +https://sentinel.rootstuff.io/bot)"
	MaxRedirects = 3
	// MaxBodyBytes caps how much of a response is read. PHP reads the whole
	// body; the cap is an explicit safety the Laravel side never had.
	MaxBodyBytes = 10 << 20
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
	// HTTP1Only turns HTTP/2 off, to tell a TLS fingerprint block from an
	// HTTP/2 fingerprint block.
	HTTP1Only bool
	// BareHeaders sends only the User-Agent, to rule the header set out.
	BareHeaders bool
	// BodySink, when set, receives the final response body (up to MaxBodyBytes).
	BodySink io.Writer
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

func defaultHeaders(o Options) map[string]string {
	h := map[string]string{
		"User-Agent":      UserAgent,
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.5",
		"X-Region":        o.Region,
		"Cache-Control":   "no-cache",
		// Accept-Encoding is left to the transport: Go then decompresses gzip
		// transparently, as Guzzle's decode_content does. PHP also offers
		// deflate; nobody serves it any more.
	}
	for k, v := range o.Headers {
		h[k] = v
	}
	return h
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
	headers := defaultHeaders(o)
	if o.BareHeaders {
		headers = map[string]string{"User-Agent": UserAgent}
	}
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

		resp, ph, closeHop, hopCancel, err := doHop(ctx, hopTimeout, connectTimeout, method, u, ip, headers, body, jar, o.HTTP1Only)
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
		n, readErr := io.Copy(sink, io.LimitReader(resp.Body, MaxBodyBytes))
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
			delete(headers, "Authorization")
			delete(headers, "Cookie")
		}

		current = next.String()
	}
}

func doHop(ctx context.Context, hopTimeout, connectTimeout time.Duration, method string, u *url.URL, ip netip.Addr, headers map[string]string, body string, jar http.CookieJar, http1Only bool) (*http.Response, phases, func(), context.CancelFunc, error) {
	hctx, cancel := context.WithTimeout(ctx, hopTimeout)
	noop := func() {}

	hc, err := connect(hctx, u, ip, connectTimeout, http1Only)
	if err != nil {
		return nil, phases{}, noop, cancel, err
	}
	ph := phases{tcp: hc.tcp, tls: hc.tls, proto: hc.proto}

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
	for k, v := range headers {
		req.Header.Set(k, v)
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
	case strings.Contains(msg, "no such host"):
		return "DNS resolution failed"
	case errors.As(err, &netErr) && netErr.Timeout() && strings.Contains(msg, "dial tcp"):
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
