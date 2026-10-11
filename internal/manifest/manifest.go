// Package manifest is the region's list of HTTP monitors as the control
// plane hands it out (POST /api/probe/sync), cached on disk so the node
// keeps checking while the control plane is unreachable.
package manifest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Monitor is one row of the manifest: the request a check makes.
type Monitor struct {
	ID                  int64             `json:"id"`
	URL                 string            `json:"url"`
	IntervalSeconds     int               `json:"interval_seconds"`
	Timeout             int               `json:"timeout"`
	Method              string            `json:"method"`
	Headers             map[string]string `json:"headers"`
	Body                *string           `json:"body"`
	AcceptedStatusCodes []string          `json:"accepted_status_codes"`
	FollowRedirects     bool              `json:"follow_redirects"`
	Auth                *Auth             `json:"auth"`
	CheckTypes          []string          `json:"check_types"`
	// NeedsBody: send the response headers and body back; the control
	// plane judges them (payment envelope, JSON assertions).
	NeedsBody     bool       `json:"needs_body"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
}

// Auth is HTTP basic auth, decrypted by the control plane for this node.
type Auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Manifest is what sync returns.
type Manifest struct {
	Region      string    `json:"region"`
	GeneratedAt time.Time `json:"generated_at"`
	Monitors    []Monitor `json:"monitors"`
	// ETag is kept beside the body so a restart resumes with If-None-Match.
	ETag string `json:"etag,omitempty"`
}

func (m *Manifest) Age(now time.Time) time.Duration {
	if m == nil || m.GeneratedAt.IsZero() {
		return -1
	}
	return now.Sub(m.GeneratedAt)
}

// Store keeps the manifest in one file, written beside and renamed, so a
// reader sees the old file or the new one and never a torn JSON. The file
// holds decrypted basic-auth credentials, hence 0600.
type Store struct{ path string }

func NewStore(dir string) *Store { return &Store{path: filepath.Join(dir, "manifest.json")} }

func (s *Store) Load() (*Manifest, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Store) Save(m *Manifest) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
