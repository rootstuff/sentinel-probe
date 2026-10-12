// Package sysinfo reads the box's vitals (CPU, memory, disk, uptime) from
// /proc and statfs so the control plane's infrastructure page can show a
// probe node the way it shows an edge. Everything is optional: on a
// platform without /proc the fields are simply absent.
package sysinfo

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Vitals is what the node reports in its sync status.
type Vitals struct {
	CPUPercent        *float64 `json:"cpu_percent,omitempty"`
	Cores             int      `json:"cores"`
	MemTotalBytes     *int64   `json:"mem_total_bytes,omitempty"`
	MemUsedBytes      *int64   `json:"mem_used_bytes,omitempty"`
	DiskTotalBytes    *int64   `json:"disk_total_bytes,omitempty"`
	DiskUsedBytes     *int64   `json:"disk_used_bytes,omitempty"`
	HostUptimeSeconds *int64   `json:"host_uptime_seconds,omitempty"`
}

// Sampler keeps the previous /proc/stat reading so CPU percent is the
// busy share since the last call (the 10s between syncs), not since boot.
type Sampler struct {
	lastBusy, lastTotal uint64
	lastAt              time.Time
	dataDir             string
}

func NewSampler(dataDir string) *Sampler { return &Sampler{dataDir: dataDir} }

// Read collects the vitals available on this platform.
func (s *Sampler) Read() Vitals {
	v := Vitals{Cores: runtime.NumCPU()}
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		if busy, total, ok := ParseStat(string(b)); ok {
			if s.lastTotal > 0 && total > s.lastTotal {
				pct := 100 * float64(busy-s.lastBusy) / float64(total-s.lastTotal)
				v.CPUPercent = &pct
			}
			s.lastBusy, s.lastTotal, s.lastAt = busy, total, time.Now()
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		if total, used, ok := ParseMeminfo(string(b)); ok {
			v.MemTotalBytes, v.MemUsedBytes = &total, &used
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if secs, err := strconv.ParseFloat(f[0], 64); err == nil {
				up := int64(secs)
				v.HostUptimeSeconds = &up
			}
		}
	}
	var fs syscall.Statfs_t
	dir := s.dataDir
	if dir == "" {
		dir = "/"
	}
	if err := syscall.Statfs(dir, &fs); err == nil && fs.Blocks > 0 {
		total := int64(fs.Blocks) * int64(fs.Bsize)
		used := int64(fs.Blocks-fs.Bfree) * int64(fs.Bsize)
		v.DiskTotalBytes, v.DiskUsedBytes = &total, &used
	}
	return v
}

// ParseStat reads the aggregate cpu line: busy and total jiffies.
func ParseStat(text string) (busy, total uint64, ok bool) {
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)[1:]
		if len(f) < 4 {
			return 0, 0, false
		}
		var vals []uint64
		for _, s := range f {
			n, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				return 0, 0, false
			}
			vals = append(vals, n)
		}
		for _, n := range vals {
			total += n
		}
		idle := vals[3]
		if len(vals) > 4 {
			idle += vals[4] // iowait counts as idle
		}
		return total - idle, total, true
	}
	return 0, 0, false
}

// ParseMeminfo returns total and used bytes, used being what the kernel
// could not hand out right now (MemTotal - MemAvailable).
func ParseMeminfo(text string) (total, used int64, ok bool) {
	var available int64 = -1
	for _, line := range strings.Split(text, "\n") {
		key, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		kb, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "MemTotal":
			total = kb * 1024
		case "MemAvailable":
			available = kb * 1024
		}
	}
	if total == 0 || available < 0 {
		return 0, 0, false
	}
	return total, total - available, true
}
