#!/usr/bin/env bash
# Puts the probe on a fresh Ubuntu box: cross-compiles for linux/amd64,
# copies the binary, the systemd unit (disabled) and the URL lists, raises
# the file-descriptor limit for the benchmark, and runs a smoke check.
#
#   scripts/node-install.sh <ipv4> [ssh-user] [region]     (default user: root)
#
# With a region, the service is configured for it. Then put the node token
# (php artisan probe:node <region> <name>) in /etc/sentinel-probe/token on
# the box and `systemctl enable --now sentinel-probe`.
#
# Then, on the box:
#   sentinel-probe check https://sentinel.rootstuff.io
#   sentinel-probe bench -local -delay 500ms -n 2000 -concurrency 500
#   sentinel-probe bench -urls /opt/sentinel-probe/bench-urls.txt -n 200 -concurrency 50
#   sentinel-probe-diag [host]      WAF diagnosis set (single, curl burst, probe burst, cadence)
set -euo pipefail
IP="${1:?usage: node-install.sh <ipv4> [user] [region]}"
USER_="${2:-root}"
REGION="${3:-}"
URL="${SENTINEL_PROBE_URL:-https://sentinel.rootstuff.io}"
VERSION="$(cd "$(dirname "$0")/.." && git describe --tags --always --dirty 2>/dev/null || echo dev)"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "building linux/amd64"
(cd "$ROOT" && mkdir -p dist && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o dist/sentinel-probe-linux-amd64 ./cmd/sentinel-probe)

echo "copying to $USER_@$IP"
scp -q "$ROOT/dist/sentinel-probe-linux-amd64" "$ROOT/deploy/sentinel-probe.service" "$ROOT/scripts/node-diag.sh" "$ROOT/scripts/node-cf.sh" "$USER_@$IP:/tmp/"
for f in "$ROOT/urls/monitors.txt" "$ROOT/urls/bench.txt"; do
  scp -q "$f" "$USER_@$IP:/tmp/sentinel-probe-$(basename "$f")"
done

ssh "$USER_@$IP" REGION="$REGION" URL="$URL" bash -s <<'REMOTE'
set -euo pipefail
id probe >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin probe
# Ping checks run the system ping, as the PHP edges do.
command -v ping >/dev/null 2>&1 || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iputils-ping >/dev/null)
install -m 0755 /tmp/sentinel-probe-linux-amd64 /usr/local/bin/sentinel-probe
install -m 0644 /tmp/sentinel-probe.service /etc/systemd/system/sentinel-probe.service
install -m 0755 /tmp/node-diag.sh /usr/local/bin/sentinel-probe-diag
install -m 0755 /tmp/node-cf.sh /usr/local/bin/sentinel-probe-cf
mkdir -p /opt/sentinel-probe
[ -f /tmp/sentinel-probe-monitors.txt ] && mv /tmp/sentinel-probe-monitors.txt /opt/sentinel-probe/urls.txt
[ -f /tmp/sentinel-probe-bench.txt ] && mv /tmp/sentinel-probe-bench.txt /opt/sentinel-probe/bench-urls.txt
mkdir -p /etc/sentinel-probe
chmod 0750 /etc/sentinel-probe
chgrp probe /etc/sentinel-probe
if [ -n "$REGION" ]; then
  printf 'SENTINEL_PROBE_REGION=%s\nSENTINEL_PROBE_URL=%s\n' "$REGION" "$URL" > /etc/sentinel-probe/env
  chmod 0640 /etc/sentinel-probe/env; chgrp probe /etc/sentinel-probe/env
fi
if [ -f /etc/sentinel-probe/token ]; then
  chmod 0640 /etc/sentinel-probe/token; chgrp probe /etc/sentinel-probe/token
fi
systemctl daemon-reload
if systemctl is-active --quiet sentinel-probe; then
  systemctl restart sentinel-probe
  echo "service restarted on the new binary"
fi
# Benchmarks open thousands of sockets; the default 1024 fds would be the first thing to fail.
grep -q 'sentinel-probe' /etc/security/limits.conf || printf '* soft nofile 65536\n* hard nofile 65536\n# sentinel-probe\n' >> /etc/security/limits.conf
echo "installed: sentinel-probe $(sentinel-probe version)"
echo "smoke:"
sentinel-probe check -region "$(hostname)" https://sentinel.rootstuff.io
REMOTE
