// Package ping is PingService: the system ping, three packets, a ten second
// budget, and the same parsing of its output.
package ping

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rootstuff/sentinel-probe/internal/target"
)

const (
	PacketCount = 3
	Timeout     = 10 * time.Second
)

// Result is the row PingMonitor stores.
type Result struct {
	Status            string  `json:"status"`
	LatencyMs         *int    `json:"latency_ms"`
	PacketLossPercent int     `json:"packet_loss_percent"`
	Error             *string `json:"error"`
}

var (
	avgRe  = regexp.MustCompile(`min/avg/max[^=]*=\s*[\d.]+/([\d.]+)/`)
	lossRe = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)%\s*packet\s*loss`)
)

func offline(msg string) Result {
	return Result{Status: "offline", PacketLossPercent: 100, Error: &msg}
}

// Run pings the monitor's target.
func Run(ctx context.Context, rawTarget string) Result {
	host := target.ExtractHost(rawTarget)
	if host == "" || !target.IsValidHost(host) {
		return offline("Invalid host in monitor URL")
	}
	if !target.Public(ctx, host, false) {
		return offline("Target host is not publicly routable")
	}

	cctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "ping", "-c", strconv.Itoa(PacketCount), host)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()

	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		return offline("Ping timed out")
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if reason := failureReason(stdout.String(), stderr.String()); reason != "" {
				return offline(reason)
			}
			return offline("Ping command failed")
		}
		return offline(simplify(err.Error()))
	}

	loss := parseLoss(stdout.String())
	if loss >= 100 {
		return offline("All ping packets lost")
	}
	return Result{Status: "online", LatencyMs: parseAvg(stdout.String()), PacketLossPercent: loss}
}

func parseAvg(out string) *int {
	m := avgRe.FindStringSubmatch(out)
	if m == nil {
		return nil
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return nil
	}
	v := int(f + 0.5)
	return &v
}

func parseLoss(out string) int {
	m := lossRe.FindStringSubmatch(out)
	if m == nil {
		return 100
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 100
	}
	return int(f + 0.5)
}

// failureReason is extractFailureReason: the first non-empty line of
// stderr, else of stdout, capped at 200 characters.
func failureReason(stdout, stderr string) string {
	combined := strings.TrimSpace(stderr)
	if combined == "" {
		combined = strings.TrimSpace(stdout)
	}
	for _, line := range strings.Split(combined, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			if len(line) > 200 {
				line = line[:200]
			}
			return line
		}
	}
	return ""
}

func simplify(msg string) string {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "timed out"), strings.Contains(lower, "timeout"):
		return "Ping timed out"
	case strings.Contains(lower, "not found"), strings.Contains(lower, "no such file"):
		return "ping binary not installed on this monitoring server"
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}
