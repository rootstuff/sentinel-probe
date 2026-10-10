#!/usr/bin/env bash
# Runs the same URLs through the Go probe and through the Laravel check
# service (locally, one tinker boot for the whole list) and prints the
# verdicts side by side plus a mismatch summary.
#
#   scripts/parity.sh urls.txt [out.tsv]
#
# Requires the uptime-watch checkout at $SENTINEL_APP (default ~/Sites/uptime-watch).
set -euo pipefail
APP="${SENTINEL_APP:-$HOME/Sites/uptime-watch}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/sentinel-probe"
URLS="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OUT="${2:-/tmp/sentinel-probe-parity.tsv}"
[ -x "$BIN" ] || (cd "$ROOT" && mkdir -p bin && go build -o bin/sentinel-probe ./cmd/sentinel-probe)

GO_JSONL="$(mktemp)"; PHP_JSONL="$(mktemp)"

# Go side: one process per URL, 8 at a time.
grep -v '^\s*#' "$URLS" | grep -v '^\s*$' | xargs -P 8 -I{} sh -c '"$0" check -region parity "$1" | jq -c --arg url "$1" ". + {url: \$url}"' "$BIN" {} > "$GO_JSONL"

# PHP side: one artisan boot, every URL through MonitorCheckService.
(cd "$APP" && php artisan tinker --execute "
\$svc = app(App\Services\MonitorCheckService::class);
foreach (file('$URLS', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as \$url) {
    if (str_starts_with(trim(\$url), '#')) { continue; }
    \$m = new App\Models\Monitor(['url' => trim(\$url), 'monitor_type' => 'http']);
    \$r = \$svc->performCheck(\$m, 'ash');
    echo json_encode(['url' => trim(\$url)] + \$r), PHP_EOL;
}
" 2>/dev/null | grep '^{' ) > "$PHP_JSONL"

jq -n -r --slurpfile go "$GO_JSONL" --slurpfile php "$PHP_JSONL" '
  ($php | map({(.url): .}) | add) as $p
  | ["url","go_status","go_code","go_error","go_ms","php_status","php_code","php_error","php_ms","match"] | @tsv,
  ($go[] | . as $g | ($p[$g.url] // {}) as $h
    | [ $g.url, $g.status, ($g.status_code // "-"), ($g.error // "-"), $g.response_time,
        ($h.status // "?"), ($h.status_code // "-"), ($h.error // "-"), ($h.response_time // "-"),
        (if $g.status == $h.status and ($g.status_code // null) == ($h.status_code // null) then "yes" else "NO" end) ]
    | @tsv)' > "$OUT"

total=$(tail -n +2 "$OUT" | wc -l | tr -d ' ')
mism=$(tail -n +2 "$OUT" | awk -F'\t' '$10=="NO"' | wc -l | tr -d ' ')
echo "parity: $((total-mism))/$total match on status + status code. Table: $OUT"
if [ "$mism" -gt 0 ]; then
  echo "mismatches:"
  tail -n +2 "$OUT" | awk -F'\t' '$10=="NO" {printf "  %-60s go=%s/%s %s | php=%s/%s %s\n", substr($1,1,60), $2,$3,$4, $6,$7,$8}'
fi
rm -f "$GO_JSONL" "$PHP_JSONL"
