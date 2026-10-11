// Package port is PortService: one TCP connect with a three second budget.
package port

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

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

// Run connects to the monitor's host and port.
func Run(ctx context.Context, rawTarget string, port int) Result {
	host := target.ExtractHost(rawTarget)
	if host == "" {
		return offline("Invalid host on monitor")
	}
	// PortService refuses private and loopback targets before validating
	// the name, and lets an unresolvable name through to the connect.
	if !target.Public(ctx, host, true) {
		return offline("Cannot monitor private or loopback addresses")
	}
	if !target.IsValidHost(host) {
		return offline("Invalid host on monitor")
	}
	if port < 1 || port > 65535 {
		return offline("Invalid port on monitor")
	}

	d := net.Dialer{Timeout: ConnectTimeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return offline(simplify(err))
	}
	conn.Close()
	ms := int(time.Since(start).Milliseconds())
	return Result{Status: "online", LatencyMs: &ms}
}

func simplify(err error) string {
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
