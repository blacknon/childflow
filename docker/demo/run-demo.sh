#!/usr/bin/env bash
set -euo pipefail

repo_root="/workspaces/childflow"
cd "$repo_root"

./docker/demo/wait-for-port.sh origin-http 8080
./docker/demo/wait-for-port.sh origin-https 8443
./docker/demo/wait-for-port.sh proxy-http 3128
./docker/demo/wait-for-port.sh proxy-https 3443

cargo test
cargo build

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

http_proxy_output="$tmpdir/http-proxy.txt"
https_proxy_output="$tmpdir/https-proxy.txt"

./target/debug/childflow \
  -o "$tmpdir/http-proxy.pcapng" \
  -p http://proxy-http:3128 \
  --proxy-user demo \
  --proxy-password demo \
  -- \
  curl -fsS http://origin-http:8080/ >"$http_proxy_output"

grep -q "origin-http-ok" "$http_proxy_output"

./target/debug/childflow \
  -o "$tmpdir/https-proxy.pcapng" \
  -p https://proxy-https:3443 \
  --proxy-user demo \
  --proxy-password demo \
  --proxy-insecure \
  -- \
  curl -kfsS https://origin-https:8443/ >"$https_proxy_output"

grep -q "origin-https-ok" "$https_proxy_output"

test -s "$tmpdir/http-proxy.pcapng"
test -s "$tmpdir/https-proxy.pcapng"

printf 'demo ok\n'
printf 'http proxy response: %s\n' "$(tr -d '\n' < "$http_proxy_output")"
printf 'https proxy response: %s\n' "$(tr -d '\n' < "$https_proxy_output")"
