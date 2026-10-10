#!/usr/bin/env bash
# Runs the same URLs through the Go probe and through the Laravel check
# service (locally, via tinker) and prints the verdicts side by side.
#
#   scripts/parity.sh urls.txt
#
# Requires the uptime-watch checkout at $SENTINEL_APP (default ~/Sites/uptime-watch).
set -euo pipefail
APP="${SENTINEL_APP:-$HOME/Sites/uptime-watch}"
BIN="$(dirname "$0")/../bin/sentinel-probe"
[ -x "$BIN" ] || (cd "$(dirname "$0")/.." && mkdir -p bin && go build -o bin/sentinel-probe ./cmd/sentinel-probe)

printf '%-60s %-8s %-5s %-28s %7s | %-8s %-5s %-28s %7s\n' URL GO code error ms PHP code error ms
while IFS= read -r url; do
  [ -z "$url" ] && continue
  case "$url" in \#*) continue;; esac
  go_json="$("$BIN" check -region parity "$url")"
  php_json="$(cd "$APP" && php artisan tinker --execute "
    \$m = new App\Models\Monitor(['url' => '$url', 'monitor_type' => 'http']);
    echo json_encode(app(App\Services\MonitorCheckService::class)->performCheck(\$m, 'ash'));
  " 2>/dev/null | tail -1)"
  g() { echo "$go_json" | jq -r "$1 // \"-\""; }
  p() { echo "$php_json" | jq -r "$1 // \"-\""; }
  printf '%-60s %-8s %-5s %-28s %7s | %-8s %-5s %-28s %7s\n' \
    "${url:0:60}" "$(g .status)" "$(g .status_code)" "$(g .error | cut -c1-28)" "$(g .response_time)" \
    "$(p .status)" "$(p .status_code)" "$(p .error | cut -c1-28)" "$(p .response_time)"
done < "$1"
