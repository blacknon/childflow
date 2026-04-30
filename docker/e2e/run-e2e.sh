#!/usr/bin/env bash
set -euo pipefail

repo_root="/workspaces/childflow"
cd "$repo_root"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/childflow-target}"
mkdir -p "$CARGO_TARGET_DIR"
bin_path="$CARGO_TARGET_DIR/debug/childflow"

run_childflow() {
  sudo -E "$bin_path" "$@"
}

cleanup() {
  sudo ip route del 10.241.0.0/24 via 10.240.0.2 dev eth0 >/dev/null 2>&1 || true
}
trap cleanup EXIT

./docker/demo/wait-for-port.sh proxy-http 3128

echo "[e2e] building childflow"
cargo build

tmpdir="$(mktemp -d)"
proxy_output="$tmpdir/proxy-http.txt"
routed_output="$tmpdir/routed-http.txt"

echo "[e2e] verifying the routed subnet is not directly reachable before adding a route"
if curl --connect-timeout 3 --max-time 5 -fsS http://origin-routed.demo:8080/ >/dev/null 2>&1; then
  echo "direct HTTP access to the routed origin unexpectedly succeeded before adding a route" >&2
  exit 1
fi

if ping -n -c 1 -W 1 ping-target.demo >/dev/null 2>&1; then
  echo "direct ping to the routed target unexpectedly succeeded before adding a route" >&2
  exit 1
fi

echo "[e2e] verifying the proxy can reach the routed origin without a client-side route"
run_childflow \
  -C wire-egress \
  -c "$tmpdir/proxy-wire-egress.pcapng" \
  -p http://proxy-http:3128 \
  -U demo \
  -P demo \
  -- \
  curl --connect-timeout 5 --max-time 15 -fsS http://origin-routed.demo:8080/ >"$proxy_output"

grep -q "routed-http-ok" "$proxy_output"
test -s "$tmpdir/proxy-wire-egress.pcapng"

echo "[e2e] installing a route to the routed subnet through the gateway container"
sudo ip route add 10.241.0.0/24 via 10.240.0.2 dev eth0

echo "[e2e] verifying routed HTTP and ICMP through childflow"
run_childflow \
  -c "$tmpdir/routed-http-child.pcapng" \
  -- \
  curl --connect-timeout 5 --max-time 15 -fsS http://origin-routed.demo:8080/ >"$routed_output"

grep -q "routed-http-ok" "$routed_output"
test -s "$tmpdir/routed-http-child.pcapng"

run_childflow \
  -C wire-egress \
  -c "$tmpdir/routed-ping-wire.pcapng" \
  -- \
  ping -n -c 1 -W 3 ping-target.demo

test -s "$tmpdir/routed-ping-wire.pcapng"

printf 'e2e ok\n'
printf 'proxy-only response: %s\n' "$(tr -d '\n' < "$proxy_output")"
printf 'routed response: %s\n' "$(tr -d '\n' < "$routed_output")"
