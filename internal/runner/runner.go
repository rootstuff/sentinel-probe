// Package runner is the probe's long-running loop: sync the manifest,
// tick every 30 seconds with the PHP edge's exact cadence, run the checks
// that are due with bounded concurrency, spool the results and post them
// in batches. Autonomy is not a mode: an unreachable control plane means
// the cached manifest keeps scheduling and the spool keeps growing.
package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rootstuff/sentinel-probe/internal/check"
	"github.com/rootstuff/sentinel-probe/internal/control"
	"github.com/rootstuff/sentinel-probe/internal/dnsq"
	"github.com/rootstuff/sentinel-probe/internal/manifest"
	"github.com/rootstuff/sentinel-probe/internal/ping"
	"github.com/rootstuff/sentinel-probe/internal/port"
	"github.com/rootstuff/sentinel-probe/internal/robots"
	"github.com/rootstuff/sentinel-probe/internal/spool"
	"github.com/rootstuff/sentinel-probe/internal/ssl"
	"github.com/rootstuff/sentinel-probe/internal/sysinfo"
	"github.com/rootstuff/sentinel-probe/internal/target"
	"github.com/rootstuff/sentinel-probe/internal/whois"
)

type Config struct {
	Region       string
	Version      string
	DataDir      string
	Concurrency  int
	SyncInterval time.Duration
	TickInterval time.Duration
	PostInterval time.Duration
	BatchSize    int
	Log          *slog.Logger
	// AlignTicks waits for the next 30s grid slot before the first tick
	// (what a node does); tests turn it off.
	AlignTicks bool
	// Phase computes a monitor's execution delay within the slot; nil means
	// StablePhase. Tests use a zero phase.
	Phase func(id int64) int64
	// AllowPrivate lets checks hit private addresses (tests only).
	AllowPrivate bool
}

type Runner struct {
	cfg    Config
	client *control.Client
	store  *manifest.Store
	spool  *spool.Spool
	log    *slog.Logger

	mu       sync.Mutex
	manifest *manifest.Manifest
	stamps   map[rowKey]int64 // manifest row -> slot of the last dispatch
	lastSync time.Time
	syncErr  string

	robots     *robots.Cache
	vitals     *sysinfo.Sampler
	inFlight   atomic.Int64
	checksMin  atomic.Int64
	sem        chan struct{}
	startedAt  time.Time
	wg         sync.WaitGroup
	postWakeup chan struct{}
}

func New(cfg Config, client *control.Client) (*Runner, error) {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 500
	}
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 10 * time.Second
	}
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = 30 * time.Second
	}
	if cfg.PostInterval <= 0 {
		cfg.PostInterval = 5 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Phase == nil {
		cfg.Phase = StablePhase
	}
	sp, err := spool.Open(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	r := &Runner{
		cfg:        cfg,
		client:     client,
		store:      manifest.NewStore(cfg.DataDir),
		spool:      sp,
		log:        cfg.Log,
		stamps:     map[rowKey]int64{},
		sem:        make(chan struct{}, cfg.Concurrency),
		startedAt:  time.Now(),
		postWakeup: make(chan struct{}, 1),
		robots:     robots.New(cfg.AllowPrivate),
		vitals:     sysinfo.NewSampler(cfg.DataDir),
	}
	if m, err := r.store.Load(); err != nil {
		r.log.Warn("cached manifest unreadable", "error", err)
	} else if m != nil {
		r.manifest = m
		r.log.Info("cached manifest loaded", "monitors", len(m.Monitors), "age", m.Age(time.Now()).Round(time.Second))
	}
	return r, nil
}

// Run blocks until ctx is cancelled, then drains in-flight checks and
// makes one last attempt to post the spool.
func (r *Runner) Run(ctx context.Context) error {
	r.sync(ctx)

	var loops sync.WaitGroup
	loops.Add(4)
	go func() { defer loops.Done(); r.every(ctx, r.cfg.SyncInterval, func() { r.sync(ctx) }) }()
	go func() { defer loops.Done(); r.ticks(ctx) }()
	go func() { defer loops.Done(); r.poster(ctx) }()
	go func() { defer loops.Done(); r.jobs(ctx) }()
	loops.Wait()

	// Shutdown: let in-flight checks finish (they are bounded by their own
	// timeouts), then one final post with a short budget.
	r.wg.Wait()
	flush, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r.post(flush)
	return r.spool.Close()
}

func (r *Runner) every(ctx context.Context, d time.Duration, f func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}

// ---- sync

// sync asks the control plane for the manifest. The control plane answers
// 304 from a version stamp when nothing changed, which is what makes a
// 10s poll affordable: a quiet poll builds nothing on either side.
//
// Monitors that are new to the manifest and have never been checked from
// this region run as soon as the manifest lands, instead of waiting for
// the next grid tick and their phase: a monitor someone just created gets
// its first result from here within the poll interval, as it does from an
// edge region.
func (r *Runner) sync(ctx context.Context) {
	r.mu.Lock()
	etag := ""
	if r.manifest != nil {
		etag = r.manifest.ETag
	}
	r.mu.Unlock()

	sctx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	m, err := r.client.Sync(sctx, etag, r.cfg.Version, r.status())

	arrivals := r.adopt(m, err)
	for _, m := range arrivals {
		r.wg.Add(1)
		go func(m manifest.Monitor) {
			defer r.wg.Done()
			r.execute(ctx, m)
		}(m)
	}
	if len(arrivals) > 0 {
		r.log.Info("new monitors checked on arrival", "count", len(arrivals))
	}
}

// adopt records the sync outcome under the lock and returns the monitors
// to check right away: present in the new manifest, absent from the old
// one, never checked from this region, not yet dispatched here.
func (r *Runner) adopt(m *manifest.Manifest, err error) []manifest.Monitor {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case err != nil:
		r.syncErr = err.Error()
		r.log.Warn("sync failed; keeping cached manifest", "error", err, "cached_monitors", r.monitorCount())
		if errors.Is(err, control.ErrUnauthorized) {
			r.log.Error("token refused; the node keeps checking from its cached manifest until the token is fixed")
		}
		return nil
	case m == nil: // 304
		r.lastSync, r.syncErr = time.Now(), ""
		if r.manifest != nil {
			r.manifest.GeneratedAt = time.Now()
		}
		return nil
	}
	if m.Region != r.cfg.Region {
		r.syncErr = "manifest is for region " + m.Region
		r.log.Error("manifest belongs to another region; ignored", "manifest_region", m.Region, "region", r.cfg.Region)
		return nil
	}

	known := map[rowKey]bool{}
	if r.manifest != nil {
		for _, old := range r.manifest.Monitors {
			known[keyOf(old)] = true
		}
	}
	var arrivals []manifest.Monitor
	slot := slotOf(time.Now())
	for _, mon := range m.Monitors {
		k := keyOf(mon)
		if _, stamped := r.stamps[k]; stamped || known[k] || mon.LastCheckedAt != nil {
			continue
		}
		r.stamps[k] = slot
		arrivals = append(arrivals, mon)
	}

	r.manifest, r.lastSync, r.syncErr = m, time.Now(), ""
	if err := r.store.Save(m); err != nil {
		r.log.Warn("manifest not cached to disk", "error", err)
	}
	r.log.Info("manifest synced", "monitors", len(m.Monitors))
	return arrivals
}

func (r *Runner) monitorCount() int {
	if r.manifest == nil {
		return 0
	}
	return len(r.manifest.Monitors)
}

// ---- on-demand jobs

// jobs long-polls the control plane for on-demand checks and runs each
// the moment it arrives: a customer's live check or the homepage hero is
// waiting on the answer. A failed wait backs off; a cancelled context
// ends the loop.
func (r *Runner) jobs(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		job, err := r.client.WaitJob(wctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.log.Warn("job wait failed", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		if job == nil {
			continue
		}
		r.wg.Add(1)
		go func(job *control.Job) {
			defer r.wg.Done()
			r.runJob(ctx, job)
		}(job)
	}
}

// runJob is the probe's /api/check-status: an ephemeral GET with the
// caller's budget, judged on 2xx/3xx, robots.txt respected.
func (r *Runner) runJob(ctx context.Context, job *control.Job) {
	if exp, err := time.Parse(time.RFC3339, job.ExpiresAt); err == nil && time.Now().After(exp) {
		r.log.Info("on-demand job expired before it ran", "job", job.ID)
		return
	}
	if job.MonitorID != 0 {
		r.runMonitorNow(ctx, job.MonitorID)
		return
	}
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-r.sem }()
	r.inFlight.Add(1)
	defer r.inFlight.Add(-1)

	var result any
	if !r.robots.Allowed(context.Background(), job.URL) {
		result = map[string]any{"status": "online", "response_time": 0, "status_code": nil, "error": nil, "robots_txt_blocked": true}
	} else {
		timeout := time.Duration(job.Timeout) * time.Second
		if timeout <= 0 {
			timeout = 15 * time.Second
		}
		follow := true
		result = check.Run(context.Background(), check.Options{
			URL:             job.URL,
			Method:          "GET",
			Region:          r.cfg.Region,
			Timeout:         timeout,
			FollowRedirects: &follow,
			AcceptedCodes:   []string{"2xx", "3xx"},
			AllowPrivate:    r.cfg.AllowPrivate,
		})
	}
	pctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := r.client.PostJobResult(pctx, job.ID, result); err != nil {
		r.log.Warn("on-demand result not delivered", "job", job.ID, "error", err)
	}
}

// runMonitorNow executes a monitor's check rows (http, ping or port; not
// its sub-checks) out of cadence and stamps them so the next tick does
// not repeat them. A monitor this node does not list is ignored.
func (r *Runner) runMonitorNow(ctx context.Context, id int64) {
	r.mu.Lock()
	var rows []manifest.Monitor
	if r.manifest != nil {
		slot := slotOf(time.Now())
		for _, m := range r.manifest.Monitors {
			k := keyOf(m)
			if m.ID == id && (k.typ == "http" || k.typ == "ping" || k.typ == "port") {
				rows = append(rows, m)
				r.stamps[k] = slot
			}
		}
	}
	r.mu.Unlock()
	if len(rows) == 0 {
		r.log.Info("check-now for a monitor this node does not list", "monitor", id)
		return
	}
	for _, m := range rows {
		r.execute(ctx, m)
	}
	r.log.Info("checked on request", "monitor", id)
}

// ---- cadence (DispatchCadence.php, kept identical)

// rowKey identifies a manifest row: a monitor appears once per check it
// gets from this region (its http check, and its ssl or dns sub-check
// when this region runs those), each on its own cadence.
type rowKey struct {
	typ string
	id  int64
}

func keyOf(m manifest.Monitor) rowKey {
	typ := m.Type
	if typ == "" {
		typ = "http"
	}
	return rowKey{typ: typ, id: m.ID}
}

func slotOf(t time.Time) int64 { return t.Unix() / 30 * 30 }

// StablePhase is DispatchCadence::stablePhase: 6-20s, constant per monitor.
func StablePhase(id int64) int64 { return 6 + int64((uint64(id)*2654435761)%15) }

func (r *Runner) isDue(m manifest.Monitor, now time.Time) bool {
	interval := int64(m.IntervalSeconds)
	if interval <= 0 {
		interval = 60
	}
	// Slots, not seconds: a node ticks on the 30s grid, so the next tick
	// after a stamp is a full slot later; measuring from mid-slot (a test
	// ticking every 200ms) would re-dispatch in a slot's last five seconds.
	if stamp, ok := r.stamps[keyOf(m)]; ok {
		return slotOf(now)-stamp >= interval-5
	}
	if m.LastCheckedAt != nil {
		return now.Sub(*m.LastCheckedAt) >= time.Duration(interval-10)*time.Second
	}
	return true
}

func (r *Runner) ticks(ctx context.Context) {
	// Align to the 30s grid like the edge daemon, then tick on it.
	if r.cfg.AlignTicks {
		first := time.Until(time.Unix(slotOf(time.Now())+30, 0))
		select {
		case <-ctx.Done():
			return
		case <-time.After(first):
		}
	}
	r.tick(ctx)
	r.every(ctx, r.cfg.TickInterval, func() { r.tick(ctx) })
}

func (r *Runner) tick(ctx context.Context) {
	now := time.Now()
	slot := slotOf(now)

	r.mu.Lock()
	if r.manifest == nil {
		r.mu.Unlock()
		return
	}
	var due []manifest.Monitor
	for _, m := range r.manifest.Monitors {
		if r.isDue(m, now) {
			due = append(due, m)
			r.stamps[keyOf(m)] = slot
		}
	}
	// Forget stamps for monitors that left the manifest.
	if len(r.stamps) > 2*len(r.manifest.Monitors)+100 {
		keep := map[rowKey]int64{}
		for _, m := range r.manifest.Monitors {
			if s, ok := r.stamps[keyOf(m)]; ok {
				keep[keyOf(m)] = s
			}
		}
		r.stamps = keep
	}
	evaluated := len(r.manifest.Monitors)
	r.mu.Unlock()

	for _, m := range due {
		runAt := time.Unix(slot+r.cfg.Phase(m.ID), 0)
		r.wg.Add(1)
		go func(m manifest.Monitor) {
			defer r.wg.Done()
			if d := time.Until(runAt); d > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(d):
				}
			}
			r.execute(ctx, m)
		}(m)
	}
	r.log.Debug("tick", "evaluated", evaluated, "dispatched", len(due))
}

func (r *Runner) execute(ctx context.Context, m manifest.Monitor) {
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-r.sem }()

	r.inFlight.Add(1)
	defer r.inFlight.Add(-1)
	r.checksMin.Add(1)

	var result any
	typ := m.Type
	if typ == "" {
		typ = "http"
	}
	switch typ {
	case "ssl":
		result = ssl.Run(context.Background(), m.URL, r.cfg.AllowPrivate)
	case "dns":
		result = dnsq.Run(context.Background(), target.ExtractHost(m.URL))
	case "domain":
		result = whois.Lookup(context.Background(), m.Domain)
	case "ping":
		result = ping.Run(context.Background(), m.URL)
	case "port":
		p := 0
		if m.Port != nil {
			p = *m.Port
		}
		result = port.Run(context.Background(), m.URL, p)
	default: // http (keywords and assertions are judged on the control plane)
		if !r.robots.Allowed(context.Background(), m.URL) {
			// As MonitorCheckService does: a robots-blocked target reads as
			// online with no request made.
			result = map[string]any{"status": "online", "response_time": 0, "status_code": nil, "error": nil, "robots_txt_blocked": true}
		} else {
			result = check.Run(context.Background(), r.options(m))
		}
	}
	checkedAt := time.Now()
	if err := r.spool.AddTyped(m.ID, typ, checkedAt, result); err != nil {
		r.log.Error("result could not be spooled", "monitor_id", m.ID, "error", err)
		return
	}
	if r.spool.Len() >= r.cfg.BatchSize {
		select {
		case r.postWakeup <- struct{}{}:
		default:
		}
	}
}

func (r *Runner) options(m manifest.Monitor) check.Options {
	follow := m.FollowRedirects
	headers := map[string]string{}
	for k, v := range m.Headers {
		headers[k] = v
	}
	if m.Auth != nil && m.Auth.Username != "" && m.Auth.Password != "" {
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(m.Auth.Username+":"+m.Auth.Password))
	}
	body := ""
	if m.Body != nil {
		body = *m.Body
	}
	timeout := time.Duration(m.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return check.Options{
		URL:             m.URL,
		Method:          m.Method,
		Region:          r.cfg.Region,
		Timeout:         timeout,
		FollowRedirects: &follow,
		AcceptedCodes:   m.AcceptedStatusCodes,
		Headers:         headers,
		Body:            body,
		AllowPrivate:    r.cfg.AllowPrivate,
		CaptureBody:     m.NeedsBody,
	}
}

// ---- posting

func (r *Runner) poster(ctx context.Context) {
	t := time.NewTicker(r.cfg.PostInterval)
	defer t.Stop()
	backoff := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.postWakeup:
		}
		if backoff > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}
		if r.post(ctx) {
			backoff = 0
		} else {
			backoff = min(max(backoff*2, 5*time.Second), time.Minute)
		}
	}
}

// post sends spooled results until the spool is empty or something fails.
// Returns false when the control plane could not be reached or refused.
func (r *Runner) post(ctx context.Context) bool {
	for {
		items := r.spool.Take(r.cfg.BatchSize)
		if len(items) == 0 {
			return true
		}
		// Captured bodies make results big; keep a request under ~4 MB.
		size := 0
		for i, it := range items {
			size += len(it.Result)
			if size > 4<<20 && i > 0 {
				items = items[:i]
				break
			}
		}
		pctx, cancel := context.WithTimeout(ctx, 55*time.Second)
		ack, err := r.client.PostResults(pctx, items)
		cancel()
		if ack != nil {
			var done []uint64
			for _, i := range ack.Accepted {
				done = append(done, items[i].Seq)
			}
			for _, i := range ack.Skipped {
				done = append(done, items[i].Seq)
			}
			r.spool.Ack(done)
			if len(ack.Failed) > 0 {
				var failed []uint64
				for _, i := range ack.Failed {
					failed = append(failed, items[i].Seq)
				}
				r.spool.Bump(failed, 3)
				r.log.Warn("control plane failed to record some results", "failed", len(ack.Failed))
			}
		}
		if err != nil {
			if errors.Is(err, control.ErrStorageUnavailable) {
				r.log.Warn("control plane storage unavailable; results stay spooled", "pending", r.spool.Len())
			} else {
				r.log.Warn("posting results failed; results stay spooled", "error", err, "pending", r.spool.Len())
			}
			return false
		}
		if len(items) < r.cfg.BatchSize {
			return true
		}
	}
}

// ---- status, as reported on every sync

func (r *Runner) status() map[string]any {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	rss := int64(ru.Maxrss)
	if runtime.GOOS == "linux" {
		rss *= 1024
	}
	age := -1
	syncedAgo := -1
	if r.manifest != nil {
		age = int(r.manifest.Age(time.Now()).Seconds())
	}
	if !r.lastSync.IsZero() {
		syncedAgo = int(time.Since(r.lastSync).Seconds())
	}
	vitals := r.vitals.Read()
	return map[string]any{
		"vitals":               vitals,
		"started_at":           r.startedAt.UTC().Format(time.RFC3339),
		"uptime_seconds":       int(time.Since(r.startedAt).Seconds()),
		"monitors":             r.monitorCount(),
		"in_flight":            r.inFlight.Load(),
		"checks_since_sync":    r.checksMin.Swap(0),
		"pending_results":      r.spool.Len(),
		"manifest_age_seconds": age,
		"last_sync_ago":        syncedAgo,
		"sync_error":           r.syncErr,
		"concurrency":          r.cfg.Concurrency,
		"rss_mb":               rss / (1 << 20),
		"heap_mb":              int64(ms.HeapAlloc) / (1 << 20),
		"load1":                loadAvg(),
		"go":                   runtime.Version(),
		"os_arch":              runtime.GOOS + "/" + runtime.GOARCH,
		"hello":                "safe",
	}
}

func loadAvg() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return -1
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return -1
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return -1
	}
	return v
}

// MarshalStatus is for the diag command.
func (r *Runner) MarshalStatus() []byte {
	b, _ := json.MarshalIndent(r.status(), "", "  ")
	return b
}
