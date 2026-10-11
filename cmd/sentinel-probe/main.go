// sentinel-probe: the London experiment. One binary that performs Sentinel
// HTTP checks with the Laravel edge's exact semantics, so the two can be
// compared on verdicts, timings and cost per in-flight check.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rootstuff/sentinel-probe/internal/check"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "check":
		runCheck(os.Args[2:])
	case "bench":
		runBench(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  sentinel-probe check [flags] <url>        one check, JSON result on stdout
  sentinel-probe bench [flags]              concurrent checks, summary on stdout

check flags: -timeout 30s -region local -accept 2xx,3xx -method GET -body '' -no-redirects -header k=v (repeatable) -allow-private
bench flags: -urls FILE | -local -delay 500ms   -n 1000 -concurrency 200 -timeout 30s -region bench`)
	os.Exit(2)
}

type headerFlags map[string]string

func (h headerFlags) String() string { return "" }
func (h headerFlags) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("header %q is not k=v", v)
	}
	h[strings.TrimSpace(k)] = strings.TrimSpace(val)
	return nil
}

func runCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	timeout := fs.Duration("timeout", 30*time.Second, "total budget, redirects included")
	region := fs.String("region", "local", "X-Region header value")
	accept := fs.String("accept", "2xx,3xx", "accepted status code patterns")
	method := fs.String("method", "GET", "HTTP method")
	body := fs.String("body", "", "request body for POST/PUT/PATCH")
	noRedirects := fs.Bool("no-redirects", false, "do not follow redirects")
	allowPrivate := fs.Bool("allow-private", false, "skip the public-address guard (local testing only)")
	headers := headerFlags{}
	fs.Var(headers, "header", "extra header k=v (repeatable)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		usage()
	}

	follow := !*noRedirects
	res := check.Run(context.Background(), check.Options{
		URL:             fs.Arg(0),
		Method:          *method,
		Region:          *region,
		Timeout:         *timeout,
		FollowRedirects: &follow,
		AcceptedCodes:   strings.Split(*accept, ","),
		Headers:         headers,
		Body:            *body,
		AllowPrivate:    *allowPrivate,
	})
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(res)
}

func runBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	urlsFile := fs.String("urls", "", "file with one URL per line")
	local := fs.Bool("local", false, "benchmark against a built-in local server instead of real URLs")
	delay := fs.Duration("delay", 500*time.Millisecond, "local server: how long each response waits (simulates network)")
	n := fs.Int("n", 1000, "total checks to run")
	concurrency := fs.Int("concurrency", 200, "checks in flight at once")
	timeout := fs.Duration("timeout", 30*time.Second, "per-check budget")
	region := fs.String("region", "bench", "X-Region header value")
	fs.Parse(args)

	var urls []string
	allowPrivate := false
	switch {
	case *local:
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(*delay)
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html><body>ok</body></html>"))
		}))
		defer srv.Close()
		urls = []string{srv.URL + "/"}
		allowPrivate = true
	case *urlsFile != "":
		f, err := os.Open(*urlsFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				urls = append(urls, line)
			}
		}
		f.Close()
	default:
		usage()
	}
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "no URLs")
		os.Exit(1)
	}

	var (
		mu       sync.Mutex
		times    []int
		online   int
		errs     = map[string]int{}
		sem      = make(chan struct{}, *concurrency)
		wg       sync.WaitGroup
		peakGo   int
		stopPeak = make(chan struct{})
	)
	go func() {
		for {
			select {
			case <-stopPeak:
				return
			case <-time.After(50 * time.Millisecond):
				if g := runtime.NumGoroutine(); g > peakGo {
					peakGo = g
				}
			}
		}
	}()

	start := time.Now()
	for i := 0; i < *n; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(u string) {
			defer func() { <-sem; wg.Done() }()
			r := check.Run(context.Background(), check.Options{URL: u, Region: *region, Timeout: *timeout, AllowPrivate: allowPrivate})
			mu.Lock()
			times = append(times, r.ResponseTime)
			if r.Status == "online" {
				online++
			} else if r.Error != nil {
				// Keyed by error and host, so a WAF that dislikes this node's
				// IP shows up by name instead of as a count.
				host := u
				if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
					host = parsed.Host
				}
				errs[*r.Error+" @ "+host]++
			}
			mu.Unlock()
		}(urls[i%len(urls)])
	}
	wg.Wait()
	close(stopPeak)
	elapsed := time.Since(start)

	sort.Ints(times)
	pct := func(p float64) int {
		if len(times) == 0 {
			return 0
		}
		return times[min(len(times)-1, int(float64(len(times))*p))]
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	maxRSS := int64(ru.Maxrss)
	if runtime.GOOS == "linux" {
		maxRSS *= 1024
	}

	out := map[string]any{
		"checks":           *n,
		"concurrency":      *concurrency,
		"elapsed_ms":       elapsed.Milliseconds(),
		"checks_per_sec":   float64(*n) / elapsed.Seconds(),
		"online":           online,
		"offline":          *n - online,
		"errors":           errs,
		"p50_ms":           pct(0.50),
		"p95_ms":           pct(0.95),
		"max_ms":           pct(1),
		"peak_rss_mb":      float64(maxRSS) / (1 << 20),
		"go_heap_sys_mb":   float64(ms.HeapSys) / (1 << 20),
		"peak_goroutines":  peakGo,
		"cpu_user_ms":      ru.Utime.Sec*1000 + int64(ru.Utime.Usec)/1000,
		"cpu_system_ms":    ru.Stime.Sec*1000 + int64(ru.Stime.Usec)/1000,
		"go_version":       runtime.Version(),
		"os_arch":          runtime.GOOS + "/" + runtime.GOARCH,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}
