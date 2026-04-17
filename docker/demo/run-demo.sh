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

./docker/demo/wait-for-port.sh proxy-http 3128
./docker/demo/wait-for-port.sh proxy-https 3443

echo "[demo] running cargo test"
cargo test
echo "[demo] running cargo build"
cargo build

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

http_proxy_output="$tmpdir/http-proxy.txt"
https_proxy_output="$tmpdir/https-proxy.txt"

if curl --connect-timeout 3 --max-time 5 -fsS http://origin-http.demo:8080/ >/dev/null 2>&1; then
  echo "direct HTTP access unexpectedly succeeded" >&2
  exit 1
fi

if curl --connect-timeout 3 --max-time 5 -kfsS https://origin-https.demo:8443/ >/dev/null 2>&1; then
  echo "direct HTTPS access unexpectedly succeeded" >&2
  exit 1
fi

echo "[demo] verifying HTTP proxy auth failure"
if run_childflow \
  -o "$tmpdir/http-auth-fail.pcapng" \
  -p http://proxy-http:3128 \
  -- \
  curl --connect-timeout 5 --max-time 10 -fsS http://origin-http.demo:8080/ >/dev/null 2>&1; then
  echo "HTTP proxy request unexpectedly succeeded without auth" >&2
  exit 1
fi

echo "[demo] verifying HTTPS proxy cert failure"
if run_childflow \
  -o "$tmpdir/https-cert-fail.pcapng" \
  -p https://proxy-https:3443 \
  --proxy-user demo \
  --proxy-password demo \
  -- \
  curl --connect-timeout 5 --max-time 10 -kfsS https://origin-https.demo:8443/ >/dev/null 2>&1; then
  echo "HTTPS proxy request unexpectedly succeeded without --proxy-insecure" >&2
  exit 1
fi

echo "[demo] verifying authenticated HTTP proxy flow"
run_childflow \
  -o "$tmpdir/http-proxy.pcapng" \
  -p http://proxy-http:3128 \
  --proxy-user demo \
  --proxy-password demo \
  -- \
  curl --connect-timeout 5 --max-time 15 -fsS http://origin-http.demo:8080/ >"$http_proxy_output"

grep -q "origin-http-ok" "$http_proxy_output"

echo "[demo] verifying authenticated HTTPS proxy flow"
run_childflow \
  -o "$tmpdir/https-proxy.pcapng" \
  -p https://proxy-https:3443 \
  --proxy-user demo \
  --proxy-password demo \
  --proxy-insecure \
  -- \
  curl --connect-timeout 5 --max-time 15 -kfsS https://origin-https.demo:8443/ >"$https_proxy_output"

grep -q "origin-https-ok" "$https_proxy_output"

test -s "$tmpdir/http-proxy.pcapng"
test -s "$tmpdir/https-proxy.pcapng"

printf 'demo ok\n'
printf 'http proxy response: %s\n' "$(tr -d '\n' < "$http_proxy_output")"
printf 'https proxy response: %s\n' "$(tr -d '\n' < "$https_proxy_output")"
