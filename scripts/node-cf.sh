#!/usr/bin/env bash
# Cloudflare-fronted customer sites: one request each per client variant,
# a few seconds apart. Prints a grid of status codes.
#
#   node-cf.sh
set -u
UA='Mozilla/5.0 (compatible; SentinelBot/1.0; +https://sentinel.rootstuff.io/bot)'
SITES="https://adambalee.com https://www.fmfcu.org https://brandywinecomm.com/ https://www.bitrefill.com https://status.vbotickets.com https://snfpaideia.upenn.edu/ https://www.microsoft.com/"
printf '%-32s %6s %6s %6s %8s %8s\n' site p-curl p-safe p-go c-h1.1 c-h2
for u in $SITES; do
  a=$(sentinel-probe check "$u" | jq -r '.status_code // .error'); sleep 2
  b=$(sentinel-probe check -hello safe "$u" | jq -r '.status_code // .error'); sleep 2
  c=$(sentinel-probe check -hello go "$u" | jq -r '.status_code // .error'); sleep 2
  d=$(curl -s -o /dev/null -m 20 -w '%{http_code}' --http1.1 -A "$UA" "$u"); sleep 2
  e=$(curl -s -o /dev/null -m 20 -w '%{http_code}' --http2 -A "$UA" "$u"); sleep 2
  printf '%-32s %6s %6s %6s %8s %8s\n' "${u:0:32}" "$a" "$b" "$c" "$d" "$e"
done
