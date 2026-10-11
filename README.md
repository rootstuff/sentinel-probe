# sentinel-probe

An experiment: can a single Go binary replace the Laravel edge worker for
Sentinel's HTTP checks, with identical verdicts, on a much smaller box?

Status: HTTP checks only. Nothing talks to the control plane yet. This repo
exists to measure, not to ship.

## What it mirrors

`internal/check` is a port of `MonitorCheckService::performCheck` and
`PinnedHttpClient::send` from the main app:

- the same request headers (SentinelBot UA, Accept, Accept-Language, X-Region, Cache-Control)
- 30s default budget, connect timeout = min(budget, max(5s, ceil(budget / 3)))
- redirects followed by hand, at most 3 hops, each hop's host resolved and
  vetted first, a throwaway cookie jar per chain, 301/302/303 turning POST
  into GET, credentials dropped when the host changes
- every hop pinned to one vetted address, IPv4 first, TLS verified against the hostname
- timing phases dns_ms, tcp_ms, tls_ms, ttfb_ms (phase-isolated, as in PHP)
- accepted status patterns (`2xx`, `3xx`, exact codes), `HTTP 503` style errors
- the five canonical error phrases: Connection timeout, Connection refused,
  DNS resolution failed, SSL certificate error, Request timeout

`internal/guard` is a port of `SsrfGuard`: private, reserved, CGNAT and
benchmarking ranges, IPv6 transition forms judged by the IPv4 they embed, a
host rejected when any of its addresses is non-public.

## Known deltas

- The probe speaks HTTP/1.1, writes its request by hand in the PHP edge's header
  order, and presents an OpenSSL-shaped TLS handshake via uTLS (`-hello curl`
  gives curl's exact hello, `-hello go` Go's stock one). PHP uses curl with
  HTTP/2. The reasoning and the London measurements are in `internal/check/hop.go`.
- Cloudflare verifies SentinelBot by the published IP list. A probe address must be
  on it before it checks Cloudflare-fronted customers; no handshake substitutes.

- Response bodies are capped at 10 MB. PHP reads everything.
- `Accept-Encoding` offers gzip only (Go handles it transparently). PHP also offers deflate.
- Multicast ranges are blocked here, not in PHP.
- No JSON assertions, no payment envelopes, no basic auth decryption, no
  result reporting. Those come after the measurement, if it's worth it.

## Run

    go test ./...
    go build -o bin/sentinel-probe ./cmd/sentinel-probe

    bin/sentinel-probe check https://sentinel.rootstuff.io
    bin/sentinel-probe check -no-redirects -accept 301 http://rootstuff.io

Load, with no real targets involved (a built-in server that sleeps 500ms per
response stands in for the internet):

    bin/sentinel-probe bench -local -delay 500ms -n 2000 -concurrency 500

Load against real URLs, one per line:

    bin/sentinel-probe bench -urls urls.txt -n 200 -concurrency 50

Verdict parity against the Laravel check service, run from a machine with
the app checked out:

    scripts/parity.sh urls.txt

## The experiment

1. Parity: the same URL list gives the same status, status code and error
   from both implementations. Response times should land within network noise.
2. Cost: peak RSS and CPU at 100, 500, 1,000 and 5,000 checks in flight.
   Today's PHP edge holds about 4.7 GB for 60 Horizon processes.
3. Then decide whether to put it on a $5 node in London beside the PHP edge
   and compare live verdicts for a week.
