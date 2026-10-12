# sentinel-probe

The monitoring node for [Sentinel](https://sentinel.rootstuff.io), the uptime
monitoring service by Rootstuff. One static Go binary runs a region: it pulls
the list of checks it is responsible for from the control plane, runs them on
their cadence, and reports the results. Every verdict is judged by the control
plane with the same rules in every region.

## What a node does

- **HTTP checks** with the request each monitor configures: method, headers,
  body, basic auth, redirect policy and accepted status codes. Timing phases
  (DNS, TCP, TLS, time to first byte) travel with every result. Response
  bodies are returned when the control plane needs to judge them (JSON
  assertions, keyword checks, payment checks).
- **Ping and port checks.**
- **SSL, DNS and domain-expiry checks** for the region the control plane
  assigns them to.
- **On-demand checks**: a long-poll for checks a customer asked for right now.
- **Verification**: when another region reports a failure, this node is asked
  to check the target immediately, so an outage is confirmed in seconds.

Targets are vetted before every request: private, reserved and
link-local addresses are refused, on the first hop and on every redirect,
and `robots.txt` is honoured.

## How it talks to the control plane

- `POST /api/probe/sync` every 10 seconds, with the node's status. The
  manifest comes back only when it changed (an ETag that moves on every
  monitor edit); a new monitor is checked the moment it arrives.
- `POST /api/probe/results` in batches. Results are spooled on disk and
  replayed after any outage of the control plane, with their original
  timestamps, so no check is lost and no alert fires on a guess.
- `POST /api/probe/jobs/wait` for on-demand and verification checks.
- `GET /api/probe/release` for the version this region should run.

Every call carries the node's own bearer token, issued per node by the
control plane and revocable there.

## Operating a node

Install on a fresh Ubuntu box (the script copies the binary, the systemd
unit and the updater, and runs a smoke check):

    scripts/node-install.sh <ipv4> root <region>

Then place the node token in `/etc/sentinel-probe/token` and
`systemctl enable --now sentinel-probe`.

Releases: a `v*` tag builds Linux amd64 and arm64 binaries with checksums
into a GitHub Release. Nodes never update themselves on their own: the
control plane pins the release each region runs, and the node's updater
timer installs that version after verifying its checksum.

## Development

    go test ./...
    go build -o bin/sentinel-probe ./cmd/sentinel-probe

    bin/sentinel-probe check https://example.com
    bin/sentinel-probe check -type ssl https://example.com
    bin/sentinel-probe check -type dns https://example.com
    bin/sentinel-probe check -type domain example.com

    bin/sentinel-probe bench -local -delay 500ms -n 2000 -concurrency 500

`scripts/parity.sh` compares verdicts with the control plane's own check
service over a URL list, for anyone changing the request logic.
