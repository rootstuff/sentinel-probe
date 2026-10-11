// Package robots mirrors RobotsTxtService: before a target is checked, its
// /robots.txt is fetched (pinned, like any probe request) and the rules for
// SentinelBot decide whether the check is made at all. The global "*"
// group is ignored, as the PHP side does. Fetched once a day per host, an
// hour after a failed fetch, and a failed fetch allows.
package robots

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rootstuff/sentinel-probe/internal/check"
)

const (
	BotName        = "SentinelBot"
	successTTL     = 24 * time.Hour
	failureTTL     = time.Hour
	fetchTimeout   = 5 * time.Second
	maxRobotsBytes = 512 * 1024
)

type rule struct {
	allow bool
	path  string
}

type entry struct {
	rules   []rule // nil: no robots.txt, or fetch failed: everything allowed
	expires time.Time
}

type Cache struct {
	mu           sync.Mutex
	hosts        map[string]entry
	allowPrivate bool
	// Fetch is swapped by tests.
	Fetch func(ctx context.Context, origin string) (status int, body string, ok bool)
}

func New(allowPrivate bool) *Cache {
	c := &Cache{hosts: map[string]entry{}, allowPrivate: allowPrivate}
	c.Fetch = c.fetch
	return c
}

// Allowed reports whether SentinelBot may request the URL.
func (c *Cache) Allowed(ctx context.Context, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return true
	}
	rules := c.rulesFor(ctx, u)
	if rules == nil {
		return true
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return allowed(rules, path)
}

func (c *Cache) rulesFor(ctx context.Context, u *url.URL) []rule {
	host := strings.ToLower(u.Host)
	c.mu.Lock()
	e, ok := c.hosts[host]
	c.mu.Unlock()
	if ok && time.Now().Before(e.expires) {
		return e.rules
	}

	status, body, ok := c.Fetch(ctx, u.Scheme+"://"+u.Host)
	var rules []rule
	ttl := failureTTL
	if ok && status >= 200 && status < 300 {
		rules = parse(body)
		ttl = successTTL
	}
	c.mu.Lock()
	c.hosts[host] = entry{rules: rules, expires: time.Now().Add(ttl)}
	c.mu.Unlock()
	return rules
}

func (c *Cache) fetch(ctx context.Context, origin string) (int, string, bool) {
	res := check.Run(ctx, check.Options{
		URL:          origin + "/robots.txt",
		Timeout:      fetchTimeout,
		Headers:      map[string]string{"User-Agent": BotName + "/1.0", "Accept": "text/plain"},
		CaptureBody:  true,
		AllowPrivate: c.allowPrivate,
	})
	if res.StatusCode == nil {
		return 0, "", false
	}
	b, _ := base64.StdEncoding.DecodeString(res.BodyB64)
	if len(b) > maxRobotsBytes {
		b = b[:maxRobotsBytes]
	}
	return *res.StatusCode, string(b), true
}

// parse keeps only the groups addressed to SentinelBot (a user-agent token
// that is a case-insensitive substring of the bot name, or the bot name
// of it), in file order.
func parse(body string) []rule {
	var rules []rule
	inOurGroup := false
	sawAgentLine := false
	for _, line := range strings.Split(body, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "user-agent":
			agent := strings.ToLower(value)
			ours := agent != "*" && (strings.Contains(strings.ToLower(BotName), agent) || strings.Contains(agent, strings.ToLower(BotName)))
			if sawAgentLine && inOurGroup {
				// Consecutive user-agent lines share a group.
				inOurGroup = inOurGroup || ours
			} else {
				inOurGroup = ours
			}
			sawAgentLine = true
		case "allow", "disallow":
			sawAgentLine = false
			if !inOurGroup || value == "" && key == "allow" {
				continue
			}
			if value == "" { // "Disallow:" alone allows everything
				continue
			}
			rules = append(rules, rule{allow: key == "allow", path: value})
		default:
			sawAgentLine = false
		}
	}
	return rules
}

// allowed applies the longest matching rule; an allow wins a tie.
func allowed(rules []rule, path string) bool {
	best := -1
	verdict := true
	for _, r := range rules {
		if n := matchLen(r.path, path); n > best || (n == best && r.allow) {
			if n >= 0 {
				best, verdict = n, r.allow
			}
		}
	}
	return verdict
}

// matchLen returns the pattern's specificity when it matches the path
// ('*' wildcards, '$' end anchor), else -1.
func matchLen(pattern, path string) int {
	anchored := strings.HasSuffix(pattern, "$")
	if anchored {
		pattern = strings.TrimSuffix(pattern, "$")
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(path[pos:], part)
		if idx < 0 {
			return -1
		}
		if i == 0 && idx != 0 {
			return -1
		}
		pos += idx + len(part)
	}
	if anchored && pos != len(path) && !(len(parts) > 1 && parts[len(parts)-1] == "") {
		return -1
	}
	return len(pattern)
}
