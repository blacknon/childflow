#!/usr/bin/env bash
set -euo pipefail

repo_root="/workspaces/childflow"
cd "$repo_root"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/childflow-target}"
mkdir -p "$CARGO_TARGET_DIR"
export PATH="$CARGO_TARGET_DIR/debug:$CARGO_TARGET_DIR/release:$PATH"
bin_path="$CARGO_TARGET_DIR/debug/childflow"
CHILDFLOW_SUDO_MODE="${CHILDFLOW_SUDO_MODE:-auto}"

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
    "$log_dir/http-origin.jsonl" \
    "$log_dir/domain-deny-origin.jsonl"
}

prepare_demo_artifact_dirs

childflow_bootstrap_blocked() {
  local stderr_file="$1"
  grep -Eq \
    'childflow: child bootstrap failed:|childflow: failed to wait for the child to finish rootless tap bootstrap|failed to create tap device|failed to make mount propagation private|failed to bind-mount .* over /etc/(resolv\.conf|hosts)|failed to open AF_PACKET channel|runtime components failed during shutdown' \
    "$stderr_file"
}

run_childflow() {
  if [[ "$CHILDFLOW_SUDO_MODE" == "always" ]]; then
    sudo -E "$bin_path" "$@"
    return
  fi

  local stdout_file stderr_file status
  stdout_file="$(mktemp)"
  stderr_file="$(mktemp)"

  set +e
  "$bin_path" "$@" >"$stdout_file" 2>"$stderr_file"
  status=$?
  set -e

  if [[ "$status" -eq 0 ]]; then
    cat "$stdout_file"
    cat "$stderr_file" >&2
    rm -f "$stdout_file" "$stderr_file"
    return 0
  fi

  if [[ "$CHILDFLOW_SUDO_MODE" == "auto" ]] && childflow_bootstrap_blocked "$stderr_file"; then
    cat "$stderr_file" >&2
    echo "[demo] childflow rootless bootstrap was blocked in this environment; retrying with sudo" >&2
    CHILDFLOW_SUDO_MODE="always"
    rm -f "$stdout_file" "$stderr_file"
    sudo -E "$bin_path" "$@"
    return
  fi

  cat "$stdout_file"
  cat "$stderr_file" >&2
  rm -f "$stdout_file" "$stderr_file"
  return "$status"
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
domain_deny_dump_output="$tmpdir/domain-deny-dump.toml"

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
  --proxy-only \
  -- \
  curl --connect-timeout 5 --max-time 10 -fsS http://origin-http.demo:8080/ >/dev/null 2>&1; then
  echo "HTTP proxy request unexpectedly succeeded without auth" >&2
  exit 1
fi

echo "[demo] verifying HTTPS proxy cert failure"
if run_childflow \
  -c "$tmpdir/https-cert-fail.pcapng" \
  -p https://proxy-https:3443 \
  --proxy-only \
  --proxy-user demo \
  --proxy-password demo \
  -- \
  curl --connect-timeout 5 --max-time 10 -kfsS https://origin-https.demo:8443/ >/dev/null 2>&1; then
  echo "HTTPS proxy request unexpectedly succeeded without --proxy-insecure" >&2
  exit 1
fi

echo "[demo] verifying authenticated HTTP proxy flow"
run_childflow \
  -c "$tmpdir/http-proxy.pcapng" \
  -p http://proxy-http:3128 \
  --proxy-only \
  --proxy-user demo \
  --proxy-password demo \
  -- \
  curl --connect-timeout 5 --max-time 15 -fsS http://origin-http.demo:8080/ >"$http_proxy_output"

grep -q "origin-http-ok" "$http_proxy_output"

echo "[demo] verifying profile-driven HTTP proxy flow"
run_childflow \
  --profile "$repo_root/docker/demo/profiles/http-origin.toml" \
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

echo "[demo] verifying reusable deny-domain profile definition"
run_childflow \
  --profile "$repo_root/docker/demo/profiles/domain-deny-origin.toml" \
  --dump-profile \
  >"$domain_deny_dump_output"

grep -q 'deny_domains = \[' "$domain_deny_dump_output"
grep -q 'origin-http.demo' "$domain_deny_dump_output"

echo "[demo] verifying authenticated HTTPS proxy flow"
run_childflow \
  -c "$tmpdir/https-proxy.pcapng" \
  -p https://proxy-https:3443 \
  --proxy-only \
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
printf 'profile http response: %s\n' "$(tr -d '\n' < "$profile_http_output")"
printf 'https proxy response: %s\n' "$(tr -d '\n' < "$https_proxy_output")"
