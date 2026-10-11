#!/usr/bin/env bash
# Runs the WAF diagnosis set against one host from this box and prints
# counts, so nothing has to be typed on a wrapping terminal line.
#
#   node-diag.sh [host]      default: www.microsoft.com
set -u
HOST="${1:-www.microsoft.com}"
UA='Mozilla/5.0 (compatible; SentinelBot/1.0; +https://sentinel.rootstuff.io/bot)'
PHP_HEADERS=(-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Accept-Language: en-US,en;q=0.5" -H "Accept-Encoding: gzip, deflate" -H "Connection: keep-alive" -H "X-Region: diag" -H "Cache-Control: no-cache")

echo "== fingerprints as the echo service sees them (curl --http1.1 vs probe)"
curl -s --http1.1 -A "$UA" https://tls.peet.ws/api/all > /tmp/fp-curl.json
sentinel-probe check -print-body https://tls.peet.ws/api/all 2>/tmp/fp-probe.json >/dev/null
for who in curl probe; do
  echo "-- $who"
  jq -r '"ja3=\(.tls.ja3_hash) ja4=\(.tls.ja4)", "ja3 text: \(.tls.ja3)", "sigalgs: \([.tls.extensions[] | select(.name | startswith("signature_algorithms")) | .signature_algorithms[]?] | join(","))"' /tmp/fp-$who.json
done

echo "== single probe check (is this address currently blocked for the probe?)"
sentinel-probe check "https://$HOST/" | jq -c '{status_code,error}'

echo "== curl burst, 20 at once, with the PHP edge's full header set"
seq 20 | xargs -P 20 -I{} curl -s -o /dev/null -w '%{http_code}\n' --http1.1 -A "$UA" "${PHP_HEADERS[@]}" "https://$HOST/" | sort | uniq -c

echo "== probe burst, 20 at once, bare headers (User-Agent only, like plain curl)"
seq 20 | xargs -P 20 -I{} sentinel-probe check -bare-headers "https://$HOST/" | jq -r '.status_code // .error' | sort | uniq -c

echo "== probe burst, 20 at once, full headers"
seq 20 | xargs -P 20 -I{} sentinel-probe check "https://$HOST/" | jq -r '.status_code // .error' | sort | uniq -c
