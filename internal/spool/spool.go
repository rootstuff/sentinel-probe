// Package spool holds check results until the control plane has
// acknowledged them. Every result is appended to a file the moment it
// exists, so a crash or a day-long control-plane outage loses nothing;
// acknowledged results are dropped and the file is compacted.
package spool

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Item is one result waiting to be posted.
type Item struct {
	Seq       uint64          `json:"seq"`
	MonitorID int64           `json:"monitor_id"`
	Type      string          `json:"type,omitempty"`
	CheckedAt time.Time       `json:"checked_at"`
	Result    json.RawMessage `json:"result"`
	Attempts  int             `json:"attempts,omitempty"`
}

// MaxAge mirrors the control plane's own replay horizon (a day).
const MaxAge = 24 * time.Hour

type Spool struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	pending []Item
	seq     uint64
	dirty   int // appends since the last compaction
}

func Open(dir string) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{path: filepath.Join(dir, "results.spool")}
	if err := s.load(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	s.file = f
	return s, nil
}

func (s *Spool) load() error {
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	cutoff := time.Now().Add(-MaxAge)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var it Item
		if json.Unmarshal(sc.Bytes(), &it) != nil {
			continue // a torn last line from a crash mid-append
		}
		if it.CheckedAt.Before(cutoff) {
			continue
		}
		s.pending = append(s.pending, it)
		if it.Seq > s.seq {
			s.seq = it.Seq
		}
	}
	return sc.Err()
}

// Add appends a result and makes it durable before returning.
func (s *Spool) Add(monitorID int64, checkedAt time.Time, result any) error {
	return s.AddTyped(monitorID, "", checkedAt, result)
}

// AddTyped appends a result of a given monitor type (http, ping, port).
func (s *Spool) AddTyped(monitorID int64, typ string, checkedAt time.Time, result any) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	it := Item{Seq: s.seq, MonitorID: monitorID, Type: typ, CheckedAt: checkedAt, Result: raw}
	line, _ := json.Marshal(it)
	if _, err := s.file.Write(append(line, '\n')); err != nil {
		return err
	}
	s.pending = append(s.pending, it)
	s.dirty++
	return nil
}

// Take returns up to n of the oldest pending items without removing them.
func (s *Spool) Take(n int) []Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > len(s.pending) {
		n = len(s.pending)
	}
	out := make([]Item, n)
	copy(out, s.pending[:n])
	return out
}

// Ack drops the given sequence numbers; Bump counts an attempt on the
// rest of a batch and drops items that have failed too often or aged out.
func (s *Spool) Ack(seqs []uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	drop := make(map[uint64]bool, len(seqs))
	for _, q := range seqs {
		drop[q] = true
	}
	s.filter(func(it Item) bool { return !drop[it.Seq] })
}

func (s *Spool) Bump(seqs []uint64, maxAttempts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bump := make(map[uint64]bool, len(seqs))
	for _, q := range seqs {
		bump[q] = true
	}
	cutoff := time.Now().Add(-MaxAge)
	for i := range s.pending {
		if bump[s.pending[i].Seq] {
			s.pending[i].Attempts++
		}
	}
	s.filter(func(it Item) bool { return it.Attempts < maxAttempts && it.CheckedAt.After(cutoff) })
}

func (s *Spool) filter(keep func(Item) bool) {
	kept := s.pending[:0]
	for _, it := range s.pending {
		if keep(it) {
			kept = append(kept, it)
		}
	}
	s.pending = kept
	s.dirty++
	if s.dirty >= 500 || len(s.pending) == 0 {
		s.compact()
	}
}

// compact rewrites the file with only what is still pending. Called with
// the lock held.
func (s *Spool) compact() {
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	w := bufio.NewWriter(f)
	for _, it := range s.pending {
		line, _ := json.Marshal(it)
		w.Write(append(line, '\n'))
	}
	if w.Flush() != nil || f.Close() != nil || os.Rename(tmp, s.path) != nil {
		return
	}
	if s.file != nil {
		s.file.Close()
	}
	s.file, _ = os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	s.dirty = 0
}

func (s *Spool) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.compact()
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}
