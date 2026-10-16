// Package port is PortService: one TCP connect with a three second budget.
package port

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rootstuff/sentinel-probe/internal/guard"
	"github.com/rootstuff/sentinel-probe/internal/target"
)

const ConnectTimeout = 3 * time.Second

// Result is the row PortMonitor stores.
type Result struct {
	Status    string  `json:"status"`
	LatencyMs *int    `json:"latency_ms"`
	Error     *string `json:"error"`
}

func offline(msg string) Result { return Result{Status: "offline", Error: &msg} }

// Run connects to the monitor's host and port, at the address the guard
// pins (the first IPv4 when there is one), so the port check and the HTTP
// check of one host reach the same server. AllowPrivate is for local
// benchmarking only.
func Run(ctx context.Context, rawTarget string, port int, allowPrivate bool) Result {
	host := target.ExtractHost(rawTarget)
	if host == "" {
		return offline("Invalid host on monitor")
	}
	// PortService refuses private and loopback targets before validating
	// the name, and lets an unresolvable name through to the connect.
	ip, err := guard.Pin(ctx, host, allowPrivate)
	if err == guard.ErrNotPublic {
		return offline("Cannot monitor private or loopback addresses")
	}
	if !target.IsValidHost(host) {
		return offline("Invalid host on monitor")
	}
	if port < 1 || port > 65535 {
		return offline("Invalid port on monitor")
	}
	if err != nil {
		return offline("DNS resolution failed")
	}

	d := net.Dialer{Timeout: ConnectTimeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil {
		return offline(Simplify(err))
	}
	conn.Close()
	ms := int(time.Since(start).Milliseconds())
	return Result{Status: "online", LatencyMs: &ms}
}

// Simplify folds a dial error into the five phrases PortService stores.
func Simplify(err error) string {
	msg := err.Error()
	lower := strings.ToLower(msg)
	var ne net.Error
	switch {
	case strings.Contains(lower, "connection refused"):
		return "Connection refused"
	case errors.As(err, &ne) && ne.Timeout(), strings.Contains(lower, "timed out"), strings.Contains(lower, "timeout"):
		return "Connection timed out"
	case strings.Contains(lower, "no such host"), strings.Contains(lower, "name or service not known"), strings.Contains(lower, "resolve"):
		return "DNS resolution failed"
	case strings.Contains(lower, "no route to host"), strings.Contains(lower, "network is unreachable"), strings.Contains(lower, "network unreachable"):
		return "Network unreachable"
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}
