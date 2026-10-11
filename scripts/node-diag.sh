#!/usr/bin/env bash
# Runs the WAF diagnosis set against one host from this box and prints
# counts, so nothing has to be typed on a wrapping terminal line.
#
#   node-diag.sh [host]      default: www.microsoft.com
set -u
HOST="${1:-www.microsoft.com}"
UA='Mozilla/5.0 (compatible; SentinelBot/1.0; +https://sentinel.rootstuff.io/bot)'

echo "== single probe check"
sentinel-probe check "https://$HOST/" | jq -c '{status_code,proto,error}'

echo "== curl burst, 20 at once"
seq 20 | xargs -P 20 -I{} curl -s -o /dev/null -w '%{http_code}\n' --http1.1 -A "$UA" "https://$HOST/" | sort | uniq -c

echo "== probe burst, 20 at once"
seq 20 | xargs -P 20 -I{} sentinel-probe check "https://$HOST/" | jq -r '.status_code // .error' | sort | uniq -c

echo "== probe at cadence, 10 requests 2s apart"
for i in $(seq 10); do sentinel-probe check "https://$HOST/" | jq -r '.status_code // .error'; sleep 2; done | sort | uniq -c
