package check

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// header is one request header. Order matters: Go's net/http writes headers
// alphabetically, which no browser or curl does, and bot managers score
// HTTP/1.1 header order. Writing the request by hand keeps the PHP edge's
// order exactly (Guzzle sends the array as given, Host first).
type header struct{ k, v string }

func orderedHeaders(o Options) []header {
	h := []header{
		{"User-Agent", UserAgent},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"Accept-Language", "en-US,en;q=0.5"},
		{"Accept-Encoding", "gzip, deflate"},
		{"Connection", "keep-alive"},
		{"X-Region", o.Region},
		{"Cache-Control", "no-cache"},
	}
	if o.BareHeaders {
		h = h[:1]
	}
	// Custom headers override by name, else append, in the order given.
	for k, v := range o.Headers {
		replaced := false
		for i := range h {
			if strings.EqualFold(h[i].k, k) {
				h[i].v, replaced = v, true
			}
		}
		if !replaced {
			h = append(h, header{k, v})
		}
	}
	return h
}

func hasHeader(h []header, name string) bool {
	for _, x := range h {
		if strings.EqualFold(x.k, name) {
			return true
		}
	}
	return false
}

func dropHeader(h []header, name string) []header {
	out := h[:0:0]
	for _, x := range h {
		if !strings.EqualFold(x.k, name) {
			out = append(out, x)
		}
	}
	return out
}

// firstByteConn stamps the moment the first response byte arrives.
type firstByteConn struct {
	net.Conn
	first time.Time
}

func (c *firstByteConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.first.IsZero() {
		c.first = time.Now()
	}
	return n, err
}

// roundTripH1 writes one HTTP/1.1 request on an already connected (and, for
// https, already handshaken) conn and reads the response. The body is left
// unread on the returned response; decodeBody unwraps gzip/deflate.
func roundTripH1(ctx context.Context, conn net.Conn, method string, u *url.URL, headers []header, body string, jar http.CookieJar) (*http.Response, time.Time, error) {
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}

	target := u.RequestURI()
	if target == "" {
		target = "/"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, target)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	for _, h := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", h.k, h.v)
	}
	if jar != nil {
		if cookies := jar.Cookies(u); len(cookies) > 0 {
			parts := make([]string, 0, len(cookies))
			for _, c := range cookies {
				parts = append(parts, c.Name+"="+c.Value)
			}
			fmt.Fprintf(&b, "Cookie: %s\r\n", strings.Join(parts, "; "))
		}
	}
	if body != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		if isJSON(body) {
			b.WriteString("Content-Type: application/json\r\n")
		}
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	} else {
		body = ""
	}
	b.WriteString("\r\n")
	b.WriteString(body)

	if _, err := io.WriteString(conn, b.String()); err != nil {
		return nil, time.Time{}, err
	}

	fbc := &firstByteConn{Conn: conn}
	req := &http.Request{Method: method, URL: u}
	resp, err := http.ReadResponse(bufio.NewReader(fbc), req)
	if err != nil {
		return nil, time.Time{}, err
	}
	if jar != nil {
		if cookies := resp.Cookies(); len(cookies) > 0 {
			jar.SetCookies(u, cookies)
		}
	}
	// The connection is single use; make the body close it.
	original := resp.Body
	resp.Body = struct {
		io.Reader
		io.Closer
	}{original, closerFunc(func() error { original.Close(); return conn.Close() })}
	return resp, fbc.first, nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// decodeBody returns a reader that unwraps the response's Content-Encoding,
// as Guzzle's decode_content does.
func decodeBody(resp *http.Response) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "gzip":
		return gzip.NewReader(resp.Body)
	case "deflate":
		// Servers disagree on whether "deflate" means zlib-wrapped or raw;
		// try zlib first and fall back to raw on a header error.
		buf := bufio.NewReader(resp.Body)
		if peek, err := buf.Peek(2); err == nil && peek[0]&0x0f == 8 && (uint16(peek[0])<<8|uint16(peek[1]))%31 == 0 {
			return zlib.NewReader(buf)
		}
		return flate.NewReader(buf), nil
	}
	return resp.Body, nil
}

func isJSON(s string) bool {
	s = strings.TrimSpace(s)
	return (strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) || (strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"))
}
