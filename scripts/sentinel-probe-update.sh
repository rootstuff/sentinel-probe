#!/usr/bin/env bash
# Runs on the node every five minutes (sentinel-probe-update.timer). Asks the
# control plane which version this region should run; when it differs from
# the installed one, downloads that release's binary, verifies its checksum,
# installs it and restarts the service. The control plane pins versions per
# region (php artisan probe:release), so a rollout is one command there and
# nothing here decides anything.
set -euo pipefail
ENV_FILE=/etc/sentinel-probe/env
TOKEN_FILE=/etc/sentinel-probe/token
BIN=/usr/local/bin/sentinel-probe
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
URL="${SENTINEL_PROBE_URL:-https://sentinel.rootstuff.io}"
TOKEN="$(cat "$TOKEN_FILE")"
ARCH="$(uname -m)"; case "$ARCH" in x86_64) ARCH=amd64;; aarch64) ARCH=arm64;; esac

answer="$(curl -fsS -m 20 -H "Authorization: Bearer $TOKEN" -H "Accept: application/json" "$URL/api/probe/release?arch=$ARCH")"
wanted="$(printf '%s' "$answer" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("version") or "")')"
installed="$("$BIN" version 2>/dev/null || echo none)"

if [ -z "$wanted" ] || [ "$wanted" = "$installed" ]; then
  exit 0
fi

download="$(printf '%s' "$answer" | python3 -c 'import json,sys; print(json.load(sys.stdin)["asset"]["url"])')"
sha="$(printf '%s' "$answer" | python3 -c 'import json,sys; print(json.load(sys.stdin)["asset"]["sha256"])')"
tmp="$(mktemp /tmp/sentinel-probe.XXXXXX)"
trap 'rm -f "$tmp"' EXIT
curl -fsSL -m 120 -o "$tmp" "$download"
echo "$sha  $tmp" | sha256sum -c --quiet
chmod 0755 "$tmp"
"$tmp" version | grep -qx "$wanted"
install -m 0755 "$tmp" "$BIN"
systemctl restart sentinel-probe
logger -t sentinel-probe-update "updated $installed -> $wanted"
