package check

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

func run(t *testing.T, o Options) Result {
	t.Helper()
	o.AllowPrivate = true
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Second
	}
	return Run(context.Background(), o)
}

func TestOnlineWithTimingAndHeaders(t *testing.T) {
	var got http.Header
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Write([]byte("hello"))
	})
	r := run(t, Options{URL: s.URL, Region: "test"})
	if r.Status != "online" || r.StatusCode == nil || *r.StatusCode != 200 || r.Error != nil {
		t.Fatalf("unexpected result %+v", r)
	}
	if got.Get("User-Agent") != UserAgent || got.Get("X-Region") != "test" || got.Get("Cache-Control") != "no-cache" {
		t.Errorf("headers not mirrored: %v", got)
	}
	if r.BodyBytes != 5 || r.PrimaryIP != "127.0.0.1" || r.Hops != 0 {
		t.Errorf("unexpected result %+v", r)
	}
}

func TestStatusPatterns(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	if r := run(t, Options{URL: s.URL}); r.Status != "offline" || *r.Error != "HTTP 503" {
		t.Fatalf("default patterns: %+v", r)
	}
	if r := run(t, Options{URL: s.URL, AcceptedCodes: []string{"5xx"}}); r.Status != "online" {
		t.Fatalf("5xx pattern: %+v", r)
	}
	if r := run(t, Options{URL: s.URL, AcceptedCodes: []string{"503"}}); r.Status != "online" {
		t.Fatalf("exact pattern: %+v", r)
	}
}

func TestRedirectsFollowThreeHopsWithCookies(t *testing.T) {
	var sawCookie bool
	var mux *http.ServeMux
	mux = http.NewServeMux()
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	mux.HandleFunc("/1", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "aff", Value: "1"})
		http.Redirect(w, r, "/2", 302)
	})
	mux.HandleFunc("/2", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/3", 302) })
	mux.HandleFunc("/3", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/end", 302) })
	mux.HandleFunc("/end", func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie("aff")
		sawCookie = err == nil
		w.WriteHeader(200)
	})
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", 301) })

	r := run(t, Options{URL: s.URL + "/1"})
	if r.Status != "online" || r.Hops != 3 || r.FinalURL != s.URL+"/end" || !sawCookie {
		t.Fatalf("three hops: %+v cookie=%v", r, sawCookie)
	}

	r = run(t, Options{URL: s.URL + "/loop"})
	if r.Status != "offline" || *r.Error != "Will not follow more than 3 redirects" {
		t.Fatalf("loop: %+v", r)
	}

	f := false
	r = run(t, Options{URL: s.URL + "/1", FollowRedirects: &f})
	if r.Status != "online" || *r.StatusCode != 302 || r.Hops != 0 {
		t.Fatalf("no follow: %+v", r)
	}
}

func TestPostBecomesGetOn302(t *testing.T) {
	var methods []string
	mux := http.NewServeMux()
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		http.Redirect(w, r, "/b", 302)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+":"+r.Header.Get("Content-Type"))
	})
	run(t, Options{URL: s.URL + "/a", Method: "POST", Body: `{"a":1}`})
	if len(methods) != 2 || methods[0] != "POST" || methods[1] != "GET:" {
		t.Fatalf("methods %v", methods)
	}
}

func TestTimeoutAndRefused(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) })
	r := run(t, Options{URL: s.URL, Timeout: time.Second})
	if r.Status != "offline" || *r.Error != "Request timeout" {
		t.Fatalf("timeout: %+v", r)
	}
	r = run(t, Options{URL: "http://127.0.0.1:1/"})
	if r.Status != "offline" || *r.Error != "Connection refused" {
		t.Fatalf("refused: %+v", r)
	}
}

func TestGuardBlocksPrivateUnlessAllowed(t *testing.T) {
	r := Run(context.Background(), Options{URL: "http://127.0.0.1:1/", Timeout: time.Second})
	if r.Status != "offline" || *r.Error != "Target host is not publicly routable" {
		t.Fatalf("guard: %+v", r)
	}
	r = Run(context.Background(), Options{URL: "https://srv-dam4f3v40ujc73fjv340", Timeout: 3 * time.Second})
	if r.Status != "offline" || *r.Error != "DNS resolution failed" {
		t.Fatalf("dns: %+v", r)
	}
}

func TestConnectTimeoutSplit(t *testing.T) {
	cases := map[time.Duration]time.Duration{
		30 * time.Second: 10 * time.Second,
		10 * time.Second: 5 * time.Second,
		3 * time.Second:  3 * time.Second,
		60 * time.Second: 20 * time.Second,
	}
	for in, want := range cases {
		if got := ConnectTimeout(in); got != want {
			t.Errorf("ConnectTimeout(%v) = %v, want %v", in, got, want)
		}
	}
}
