package sysinfo

import "testing"

func TestParsers(t *testing.T) {
	busy, total, ok := ParseStat("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n")
	if !ok || total != 1000 || busy != 150 {
		t.Errorf("stat: ok=%v busy=%d total=%d", ok, busy, total)
	}
	mt, mu, ok := ParseMeminfo("MemTotal:       1000000 kB\nMemFree:         100000 kB\nMemAvailable:    600000 kB\n")
	if !ok || mt != 1000000*1024 || mu != 400000*1024 {
		t.Errorf("meminfo: ok=%v total=%d used=%d", ok, mt, mu)
	}
	if _, _, ok := ParseMeminfo("MemTotal: 10 kB\n"); ok {
		t.Error("meminfo without MemAvailable must not be ok")
	}

	// Two reads give a percent for the interval between them.
	s := &Sampler{}
	s.lastBusy, s.lastTotal = 100, 1000
	busy, total, _ = ParseStat("cpu  200 0 100 1600 100 0 0 0 0 0\n")
	pct := 100 * float64(busy-s.lastBusy) / float64(total-s.lastTotal)
	if pct < 19.9 || pct > 20.1 {
		t.Errorf("cpu percent %.2f, want 20", pct)
	}
}
