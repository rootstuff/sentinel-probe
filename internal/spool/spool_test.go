package spool

import (
	"testing"
	"time"
)

func TestSpoolRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i <= 3; i++ {
		if err := s.Add(i, time.Now(), map[string]any{"status": "online"}); err != nil {
			t.Fatal(err)
		}
	}
	items := s.Take(2)
	if len(items) != 2 || items[0].MonitorID != 1 || items[1].MonitorID != 2 {
		t.Fatalf("take: %+v", items)
	}
	s.Ack([]uint64{items[0].Seq})
	s.Bump([]uint64{items[1].Seq}, 2)
	if s.Len() != 2 {
		t.Fatalf("len after ack: %d", s.Len())
	}
	s.Bump([]uint64{items[1].Seq}, 2) // second failure hits maxAttempts
	if s.Len() != 1 {
		t.Fatalf("len after max attempts: %d", s.Len())
	}
	s.Close()

	// Reload from disk: the survivor is there, with its sequence.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 1 || s2.Take(1)[0].MonitorID != 3 {
		t.Fatalf("reload: %+v", s2.Take(1))
	}
	if err := s2.Add(4, time.Now(), map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if got := s2.Take(2)[1].Seq; got != 4 {
		t.Errorf("sequence should continue past the reloaded max, got %d", got)
	}
}
