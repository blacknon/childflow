#!/usr/bin/env bash
set -euo pipefail

repo_root="/workspaces/childflow"
cd "$repo_root"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/childflow-target}"
mkdir -p "$CARGO_TARGET_DIR"
export PATH="$CARGO_TARGET_DIR/debug:$CARGO_TARGET_DIR/release:$PATH"

prepare_demo_artifact_dirs() {
  local capture_dir="$repo_root/docker/demo/profiles/captures"
  local log_dir="$repo_root/docker/demo/profiles/logs"

  if ! mkdir -p "$capture_dir" "$log_dir" 2>/dev/null; then
    sudo install -d -m 0775 -o "$(id -un)" -g "$(id -gn)" "$capture_dir" "$log_dir"
  fi

  if [[ ! -w "$capture_dir" || ! -w "$log_dir" ]]; then
    sudo chown "$(id -un):$(id -gn)" "$capture_dir" "$log_dir"
  fi

  sudo rm -f \
    "$capture_dir/http-origin.pcapng" \
    "$log_dir/http-origin.jsonl"
}

prepare_demo_artifact_dirs

run_childflow() {
  childflow "$@"
}

resolve_service_ipv4() {
  local host="$1"
  getent ahostsv4 "$host" | awk 'NR == 1 { print $1 }'
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
profile_http_output="$tmpdir/profile-http.txt"
profile_dump_output="$tmpdir/profile-dump.toml"
profile_ip_path="$tmpdir/http-origin-ip.toml"

origin_http_ip="$(resolve_service_ipv4 origin-http.demo)"
origin_https_ip="$(resolve_service_ipv4 origin-https.demo)"

if [[ -z "$origin_http_ip" || -z "$origin_https_ip" ]]; then
  echo "failed to resolve demo origin container IPs" >&2
  exit 1
fi

origin_http_url="http://$origin_http_ip:8080/"
origin_https_url="https://$origin_https_ip:8443/"

cat >"$profile_ip_path" <<EOF
extends = "$repo_root/docker/demo/profiles/base.toml"
capture = "$repo_root/docker/demo/profiles/captures/http-origin.pcapng"
flow_log = "$repo_root/docker/demo/profiles/logs/http-origin.jsonl"
command = [
  "curl",
  "--connect-timeout",
  "5",
  "--max-time",
  "15",
  "-fsS",
  "$origin_http_url",
]
EOF

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
  -c "$tmpdir/http-auth-fail.pcapng" \
  -p http://proxy-http:3128 \
  -- \
  curl --connect-timeout 5 --max-time 10 -fsS "$origin_http_url" >/dev/null 2>&1; then
  echo "HTTP proxy request unexpectedly succeeded without auth" >&2
  exit 1
fi

echo "[demo] verifying HTTPS proxy cert failure"
if run_childflow \
  -c "$tmpdir/https-cert-fail.pcapng" \
  -p https://proxy-https:3443 \
  --proxy-user demo \
  --proxy-password demo \
  -- \
  curl --connect-timeout 5 --max-time 10 -kfsS "$origin_https_url" >/dev/null 2>&1; then
  echo "HTTPS proxy request unexpectedly succeeded without --proxy-insecure" >&2
  exit 1
fi

echo "[demo] verifying authenticated HTTP proxy flow"
run_childflow \
  -c "$tmpdir/http-proxy.pcapng" \
  -p http://proxy-http:3128 \
  --proxy-user demo \
  --proxy-password demo \
  -- \
  curl --connect-timeout 5 --max-time 15 -fsS "$origin_http_url" >"$http_proxy_output"

grep -q "origin-http-ok" "$http_proxy_output"

echo "[demo] verifying profile-driven HTTP proxy flow"
run_childflow \
  --profile "$profile_ip_path" \
  >"$profile_http_output"

grep -q "origin-http-ok" "$profile_http_output"
test -s "$repo_root/docker/demo/profiles/captures/http-origin.pcapng"
test -s "$repo_root/docker/demo/profiles/logs/http-origin.jsonl"

echo "[demo] verifying merged profile dump"
run_childflow \
  --profile "$repo_root/docker/demo/profiles/http-origin.toml" \
  --deny-cidr 198.51.100.0/24 \
  --dump-profile \
  >"$profile_dump_output"

grep -q 'proxy = "http://proxy-http:3128"' "$profile_dump_output"
grep -q 'default_policy = "deny"' "$profile_dump_output"
grep -q 'deny_cidrs = \[' "$profile_dump_output"
grep -q '198.51.100.0/24' "$profile_dump_output"

echo "[demo] verifying authenticated HTTPS proxy flow"
run_childflow \
  -c "$tmpdir/https-proxy.pcapng" \
  -p https://proxy-https:3443 \
  --proxy-user demo \
  --proxy-password demo \
  --proxy-insecure \
  -- \
  curl --connect-timeout 5 --max-time 15 -kfsS "$origin_https_url" >"$https_proxy_output"

grep -q "origin-https-ok" "$https_proxy_output"

test -s "$tmpdir/http-proxy.pcapng"
test -s "$tmpdir/https-proxy.pcapng"

printf 'demo ok\n'
printf 'http proxy response: %s\n' "$(tr -d '\n' < "$http_proxy_output")"
printf 'profile http response: %s\n' "$(tr -d '\n' < "$profile_http_output")"
printf 'https proxy response: %s\n' "$(tr -d '\n' < "$https_proxy_output")"
