#!/usr/bin/env bash
# WAF diagnosis at a monitor's cadence: single checks, then probe and curl
# alternating a few seconds apart. No bursts: a burst poisons the address
# for every client and then proves nothing.
#
#   node-diag.sh [host] [rounds]      default: www.microsoft.com, 10
set -u
HOST="${1:-www.microsoft.com}"
ROUNDS="${2:-10}"
UA='Mozilla/5.0 (compatible; SentinelBot/1.0; +https://sentinel.rootstuff.io/bot)'

echo "== fingerprints (curl --http1.1 vs probe); all three JA4 parts should match"
curl -s --http1.1 -A "$UA" https://tls.peet.ws/api/all | jq -r '"curl   ja3=\(.tls.ja3_hash) ja4=\(.tls.ja4)"'
sentinel-probe check -print-body https://tls.peet.ws/api/all 2>&1 >/dev/null | jq -r '"probe  ja3=\(.tls.ja3_hash) ja4=\(.tls.ja4)"'

echo "== $HOST, $ROUNDS rounds of probe then curl, 3s apart"
for i in $(seq "$ROUNDS"); do
  p=$(sentinel-probe check "https://$HOST/" | jq -r '.status_code // .error')
  sleep 3
  c=$(curl -s -o /dev/null -w '%{http_code}' --http1.1 -A "$UA" "https://$HOST/")
  sleep 3
  echo "probe=$p curl=$c"
done | sort | uniq -c
