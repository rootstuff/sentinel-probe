package runner

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootstuff/sentinel-probe/internal/control"
)

// fakeControl is the two probe endpoints with recording and a kill switch.
type fakeControl struct {
	t         *testing.T
	target    string
	mu        sync.Mutex
	syncs     []map[string]any
	posted    [][]map[string]any
	tokens    []string
	etags     []string
	down      atomic.Bool // results answer 503 with nothing accepted
	srv       *httptest.Server
	manifest  func() map[string]any
	tag       string // the ETag the fake currently serves; a sync carrying it is a 304
	syncCalls atomic.Int64
	// jobs are handed out one per wait call; results land by path.
	jobs       []map[string]any
	jobResults map[string]map[string]any
}

// setManifest swaps the served manifest and moves the tag, as a control
// plane does when a monitor changes.
func (f *fakeControl) setManifest(tag string, m func() map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tag, f.manifest = tag, m
}

func newFakeControl(t *testing.T, target string) *fakeControl {
	f := &fakeControl{t: t, target: target, tag: `"v1"`, jobResults: map[string]map[string]any{}}
	f.manifest = func() map[string]any {
		return map[string]any{
			"region":       "test",
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"monitors": []map[string]any{{
				"id": 7, "type": "port", "url": "port.invalid", "port": 1, "interval_seconds": 30,
			}, {
				"id": 42, "type": "http", "url": target + "/ok", "interval_seconds": 30, "timeout": 5, "method": "GET",
				"headers": map[string]string{"X-Custom": "1"}, "body": nil, "accepted_status_codes": []string{"2xx"},
				"follow_redirects": true, "auth": map[string]string{"username": "u", "password": "p"},
				"check_types": []string{"http", "json"}, "needs_body": true, "last_checked_at": nil,
			}},
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/probe/sync", func(w http.ResponseWriter, r *http.Request) {
		f.syncCalls.Add(1)
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.syncs = append(f.syncs, body)
		f.tokens = append(f.tokens, r.Header.Get("Authorization"))
		f.etags = append(f.etags, r.Header.Get("If-None-Match"))
		tag, manifest := f.tag, f.manifest
		f.mu.Unlock()
		if r.Header.Get("If-None-Match") == tag {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", tag)
		json.NewEncoder(w).Encode(manifest())
	})
	mux.HandleFunc("/api/probe/jobs/wait", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		var job map[string]any
		if len(f.jobs) > 0 {
			job, f.jobs = f.jobs[0], f.jobs[1:]
		}
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"job": job})
	})
	mux.HandleFunc("/api/probe/jobs/", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Result map[string]any `json:"result"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.jobResults[r.URL.Path] = body.Result
		f.mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/probe/results", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Results []map[string]any `json:"results"`
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		if f.down.Load() {
			w.WriteHeader(503)
			json.NewEncoder(w).Encode(map[string]any{"accepted": []int{}, "skipped": []int{}, "failed": []int{}})
			return
		}
		f.mu.Lock()
		f.posted = append(f.posted, body.Results)
		f.mu.Unlock()
		idx := make([]int, len(body.Results))
		for i := range idx {
			idx[i] = i
		}
		json.NewEncoder(w).Encode(map[string]any{"accepted": idx, "skipped": []int{}, "failed": []int{}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeControl) postedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.posted {
		n += len(b)
	}
	return n
}

func newTestRunner(t *testing.T, f *fakeControl, dir string) *Runner {
	t.Helper()
	r, err := New(Config{
		Region: "test", Version: "test", DataDir: dir, Concurrency: 10,
		SyncInterval: 200 * time.Millisecond, TickInterval: 200 * time.Millisecond, PostInterval: 100 * time.Millisecond, JobPollInterval: 50 * time.Millisecond,
		BatchSize: 100, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Phase: func(int64) int64 { return 0 }, AllowPrivate: true,
	}, control.New(f.srv.URL, "spn_test", "test"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestEndToEnd(t *testing.T) {
	var gotAuth, gotCustom string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotCustom = r.Header.Get("Authorization"), r.Header.Get("X-Custom")
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	f := newFakeControl(t, target.URL)
	r := newTestRunner(t, f, t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	waitFor(t, 8*time.Second, func() bool { return f.postedCount() >= 2 && f.syncCalls.Load() >= 2 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if n := f.postedCount(); n != 2 {
		t.Errorf("one check per monitor in a 30s interval expected, posted %d", n)
	}
	if r.spool.Len() != 0 {
		t.Errorf("spool should be drained, has %d", r.spool.Len())
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokens[0] != "Bearer spn_test" {
		t.Errorf("token header %q", f.tokens[0])
	}
	if f.syncs[0]["version"] != "test" || f.syncs[0]["status"].(map[string]any)["monitors"] == nil {
		t.Errorf("status not reported: %v", f.syncs[0])
	}
	if len(f.etags) < 2 || f.etags[1] != `"v1"` {
		t.Errorf("second sync should carry the ETag, got %v", f.etags)
	}
	var item, portItem map[string]any
	for _, batch := range f.posted {
		for _, it := range batch {
			switch it["monitor_id"].(float64) {
			case 42:
				item = it
			case 7:
				portItem = it
			}
		}
	}
	if item == nil || portItem == nil {
		t.Fatalf("expected both monitors posted: %v", f.posted)
	}
	if portItem["type"] != "port" || portItem["result"].(map[string]any)["status"] != "offline" {
		t.Errorf("port result: %v", portItem)
	}
	if item["type"] != "http" {
		t.Errorf("http result should carry its type: %v", item)
	}
	if _, err := time.Parse(time.RFC3339, item["checked_at"].(string)); err != nil {
		t.Errorf("checked_at %v", item["checked_at"])
	}
	res := item["result"].(map[string]any)
	if res["status"] != "online" || res["status_code"].(float64) != 200 {
		t.Errorf("result %v", res)
	}
	if gotAuth != "Basic dTpw" || gotCustom != "1" {
		t.Errorf("request headers auth=%q custom=%q", gotAuth, gotCustom)
	}
	if res["body_b64"] == nil || res["headers"] == nil {
		t.Errorf("needs_body monitor should post body and headers: %v", res)
	}
}

func TestOutageSpoolsAndReplays(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer target.Close()
	f := newFakeControl(t, target.URL)
	dir := t.TempDir()

	// First run: get a manifest cached, then take the control plane down
	// for results.
	r := newTestRunner(t, f, dir)
	f.down.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	waitFor(t, 5*time.Second, func() bool { return r.spool.Len() >= 1 })
	cancel()
	<-done
	if f.postedCount() != 0 {
		t.Fatalf("nothing should have been accepted while down, got %d", f.postedCount())
	}

	// Second run from the same data dir: the spooled result is replayed
	// once the control plane answers, and the cached manifest was loaded
	// before the first sync.
	f.down.Store(false)
	r2 := newTestRunner(t, f, dir)
	if r2.manifest == nil || len(r2.manifest.Monitors) != 2 {
		t.Fatal("cached manifest not loaded on restart")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- r2.Run(ctx2) }()
	waitFor(t, 5*time.Second, func() bool { return f.postedCount() >= 1 })
	cancel2()
	<-done2
	if r2.spool.Len() != 0 {
		t.Errorf("spool not drained after replay: %d", r2.spool.Len())
	}
}

func TestNewMonitorRunsOnArrival(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer target.Close()
	f := newFakeControl(t, target.URL)
	r := newTestRunner(t, f, t.TempDir())
	// Ticks are far apart: only arrival dispatch can run a new monitor
	// inside the wait below.
	r.cfg.TickInterval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	waitFor(t, 5*time.Second, func() bool { return f.postedCount() >= 2 })

	// The first manifest's monitors were new too, but they ran on the
	// first tick. Now a monitor appears that this region never checked.
	checkedBefore := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	f.setManifest(`"v2"`, func() map[string]any {
		return map[string]any{
			"region": "test", "generated_at": time.Now().UTC().Format(time.RFC3339),
			"monitors": []map[string]any{
				{"id": 42, "type": "http", "url": target.URL + "/ok", "interval_seconds": 30, "timeout": 5, "method": "GET",
					"accepted_status_codes": []string{"2xx"}, "follow_redirects": true, "last_checked_at": nil},
				{"id": 99, "type": "http", "url": target.URL + "/new", "interval_seconds": 30, "timeout": 5, "method": "GET",
					"accepted_status_codes": []string{"2xx"}, "follow_redirects": true, "last_checked_at": nil},
				// Already checked from this region by a previous node: it
				// waits for its slot like any other.
				{"id": 100, "type": "http", "url": target.URL + "/old", "interval_seconds": 30, "timeout": 5, "method": "GET",
					"accepted_status_codes": []string{"2xx"}, "follow_redirects": true, "last_checked_at": checkedBefore},
			},
		}
	})

	posted := func(id float64) bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, batch := range f.posted {
			for _, it := range batch {
				if it["monitor_id"].(float64) == id {
					return true
				}
			}
		}
		return false
	}
	waitFor(t, 5*time.Second, func() bool { return posted(99) })
	if posted(100) {
		t.Error("a monitor this region had checked before must wait for its slot, not run on arrival")
	}
	if n := f.postedCount(); n != 3 {
		t.Errorf("expected exactly one arrival check on top of the first tick's two, got %d", n)
	}
	cancel()
	<-done
}

func TestSslRowRunsBesideTheHttpRowOfTheSameMonitor(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer target.Close()
	f := newFakeControl(t, target.URL)
	// The same monitor id twice: its http check and its ssl sub-check are
	// separate rows with separate cadences.
	f.setManifest(`"v1"`, func() map[string]any {
		return map[string]any{
			"region": "test", "generated_at": time.Now().UTC().Format(time.RFC3339),
			"monitors": []map[string]any{
				{"id": 5, "type": "http", "url": target.URL + "/", "interval_seconds": 30, "timeout": 5, "method": "GET",
					"accepted_status_codes": []string{"2xx"}, "follow_redirects": true, "last_checked_at": nil},
				{"id": 5, "type": "ssl", "url": target.URL + "/", "interval_seconds": 1800, "last_checked_at": nil},
			},
		}
	})
	r := newTestRunner(t, f, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	waitFor(t, 8*time.Second, func() bool { return f.postedCount() >= 2 })
	cancel()
	<-done

	var sslItem, httpItem map[string]any
	f.mu.Lock()
	for _, batch := range f.posted {
		for _, it := range batch {
			switch it["type"] {
			case "ssl":
				sslItem = it
			case "http":
				httpItem = it
			}
		}
	}
	f.mu.Unlock()
	if sslItem == nil || httpItem == nil {
		t.Fatalf("both rows should post: %v", f.posted)
	}
	res := sslItem["result"].(map[string]any)
	if res["not_after"] == nil || res["tls_protocol"] != "TLSv1.3" || res["error"] != nil {
		t.Errorf("ssl facts: %v", res)
	}
	if n := f.postedCount(); n != 2 {
		t.Errorf("one check per row expected, posted %d", n)
	}
}

func TestOnDemandJobRunsOnArrivalAndPostsItsResult(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(503)
	}))
	defer target.Close()
	f := newFakeControl(t, target.URL)
	f.jobs = []map[string]any{
		{"id": "job-expired", "url": target.URL + "/", "timeout": 5, "source_region": "ash", "expires_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)},
		{"id": "job-1", "url": target.URL + "/", "timeout": 5, "source_region": "ash", "expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)},
	}
	r := newTestRunner(t, f, t.TempDir())
	r.cfg.TickInterval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	waitFor(t, 5*time.Second, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.jobResults["/api/probe/jobs/job-1/result"] != nil
	})
	cancel()
	<-done

	f.mu.Lock()
	defer f.mu.Unlock()
	res := f.jobResults["/api/probe/jobs/job-1/result"]
	if res["status"] != "offline" || res["status_code"].(float64) != 503 {
		t.Errorf("on-demand result: %v", res)
	}
	if _, ran := f.jobResults["/api/probe/jobs/job-expired/result"]; ran {
		t.Error("an expired job must not run")
	}
}

func TestCheckNowRunsTheMonitorRowOutOfCadence(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer target.Close()
	f := newFakeControl(t, target.URL)
	// Monitor 42 is listed; 777 is not.
	f.jobs = []map[string]any{
		{"id": "run-1", "monitor_id": 42, "expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)},
		{"id": "run-2", "monitor_id": 777, "expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)},
	}
	r := newTestRunner(t, f, t.TempDir())
	r.cfg.TickInterval = time.Hour // the first tick runs everything once; nothing after

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	// First tick: 2 rows (42 http + 7 port). Then the check-now: 42 again.
	waitFor(t, 8*time.Second, func() bool { return f.postedCount() >= 3 })
	cancel()
	<-done

	f.mu.Lock()
	defer f.mu.Unlock()
	n42, total := 0, 0
	for _, batch := range f.posted {
		for _, it := range batch {
			total++
			if it["monitor_id"].(float64) == 42 {
				n42++
			}
		}
	}
	if n42 != 2 {
		t.Errorf("monitor 42 should have its tick check plus one check-now, got %d", n42)
	}
	if total != 3 {
		t.Errorf("an unlisted monitor must not run, posted %d", total)
	}
	if len(f.jobResults) != 0 {
		t.Errorf("a check-now posts no job result: %v", f.jobResults)
	}
}

func TestStablePhaseMatchesPHP(t *testing.T) {
	// 6 + (id * 2654435761) % 15, as DispatchCadence::stablePhase computes it.
	cases := map[int64]int64{1: 6 + (2654435761 % 15), 2: 6 + (2*2654435761)%15, 237: 6 + (237*2654435761)%15}
	for id, want := range cases {
		if got := StablePhase(id); got != want {
			t.Errorf("StablePhase(%d) = %d, want %d", id, got, want)
		}
		if p := StablePhase(id); p < 6 || p > 20 {
			t.Errorf("phase out of range: %d", p)
		}
	}
}
