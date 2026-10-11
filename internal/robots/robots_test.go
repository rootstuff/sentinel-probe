package robots

import (
	"context"
	"testing"
)

func TestRulesForSentinelBotOnly(t *testing.T) {
	body := `
User-agent: *
Disallow: /

User-agent: Googlebot
Disallow: /private/

User-agent: SentinelBot
Disallow: /admin/
Allow: /admin/public
Disallow: /*.pdf$
`
	rules := parse(body)
	cases := map[string]bool{
		"/":                     true, // the global group is ignored
		"/private/x":            true, // Googlebot's rules are not ours
		"/admin/":               false,
		"/admin/users":          false,
		"/admin/public/page":    true, // longer allow wins
		"/files/report.pdf":     false,
		"/files/report.pdf?x=1": true, // anchored: not the end
	}
	for path, want := range cases {
		if got := allowed(rules, path); got != want {
			t.Errorf("allowed(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestFetchFailureAllowsAndIsCached(t *testing.T) {
	c := New(false)
	calls := 0
	c.Fetch = func(context.Context, string) (int, string, bool) { calls++; return 0, "", false }
	if !c.Allowed(context.Background(), "https://example.com/anything") || !c.Allowed(context.Background(), "https://example.com/else") {
		t.Fatal("a failed fetch must allow")
	}
	if calls != 1 {
		t.Fatalf("fetch should be cached, called %d times", calls)
	}
}

func TestBlockedPathIsNotAllowed(t *testing.T) {
	c := New(false)
	c.Fetch = func(context.Context, string) (int, string, bool) {
		return 200, "User-agent: sentinelbot\nDisallow: /health\n", true
	}
	if c.Allowed(context.Background(), "https://example.com/health") {
		t.Fatal("blocked path allowed")
	}
	if !c.Allowed(context.Background(), "https://example.com/") {
		t.Fatal("other path blocked")
	}
}
