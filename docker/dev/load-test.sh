#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  docker/dev/load-test.sh <scenario> [duration_sec] [mode]

Scenarios:
  steady-http         Low-rate long run against a local HTTP server
  short-tcp           High-rate short-lived TCP connections against a local HTTP server
  dns-unique          Unique DNS names to stress flow-log DNS correlation state
  deny-domain-storm   Unique denied DNS names to stress policy_violation logging
  compare-observability
                      Run steady-http in capture, flow-log, and both modes

Modes:
  both        Enable pcap and flow-log output
  capture     Enable only pcap output
  flow-log    Enable only flow-log output
  none        Disable both artifacts

Examples:
  docker/dev/load-test.sh steady-http 600 both
  docker/dev/load-test.sh dns-unique 1800 flow-log
  docker/dev/load-test.sh compare-observability 300

Environment overrides:
  CHILDFLOW_BIN            Path to childflow binary (default: childflow)
  CHILDFLOW_BACKEND_ARGS   Extra backend args, for example: --root
  CHILDFLOW_INTERVAL       Per-request sleep interval in seconds
  CHILDFLOW_WORKERS        Worker count for short-tcp
  CHILDFLOW_MONITOR_SEC    Metric sample interval in seconds
  CHILDFLOW_HTTP_PORT      Local HTTP port override
EOF
}

if [[ "${1:-}" == "" || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

SCENARIO="$1"
DURATION="${2:-300}"
MODE="${3:-both}"

CHILDFLOW_BIN="${CHILDFLOW_BIN:-childflow}"
CHILDFLOW_BACKEND_ARGS="${CHILDFLOW_BACKEND_ARGS:-}"
CHILDFLOW_INTERVAL="${CHILDFLOW_INTERVAL:-0.20}"
CHILDFLOW_WORKERS="${CHILDFLOW_WORKERS:-8}"
CHILDFLOW_MONITOR_SEC="${CHILDFLOW_MONITOR_SEC:-5}"
CHILDFLOW_HTTP_PORT="${CHILDFLOW_HTTP_PORT:-18080}"
CHILDFLOW_HTTP_HOST="${CHILDFLOW_HTTP_HOST:-}"
CHILDFLOW_HTTP_TARGET=""

if ! command -v "$CHILDFLOW_BIN" >/dev/null 2>&1; then
  echo "error: childflow binary not found at '$CHILDFLOW_BIN'" >&2
  echo "build first with 'cargo build' inside docker/dev, or set CHILDFLOW_BIN" >&2
  exit 1
fi

if ! command -v /bin/busybox >/dev/null 2>&1; then
  echo "error: /bin/busybox is required for this harness" >&2
  exit 1
fi

SUMMARY_SCRIPT="$(cd "$(dirname "$0")" && pwd)/summarize-load-test.sh"

timestamp="$(date +%Y%m%d-%H%M%S)"
base_dir="/tmp/childflow-loadtest/${SCENARIO}-${timestamp}"
mkdir -p "$base_dir"

server_pid=""
monitor_pid=""

cleanup() {
  if [[ -n "$monitor_pid" ]]; then
    kill "$monitor_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

start_http_server() {
  local root_dir="$base_dir/www"
  mkdir -p "$root_dir"
  printf 'ok\n' >"$root_dir/index.html"
  if [[ -z "$CHILDFLOW_HTTP_HOST" ]]; then
    CHILDFLOW_HTTP_HOST="$(
      ip -4 route get 1.1.1.1 2>/dev/null | awk '
        {
          for (i = 1; i <= NF; i++) {
            if ($i == "src" && (i + 1) <= NF) {
              print $(i + 1)
              exit
            }
          }
        }
      '
    )"
  fi
  if [[ -z "$CHILDFLOW_HTTP_HOST" ]]; then
    echo "error: failed to discover a non-loopback host IPv4 address for the local HTTP server" >&2
    echo "set CHILDFLOW_HTTP_HOST explicitly and retry" >&2
    exit 1
  fi
  CHILDFLOW_HTTP_TARGET="http://${CHILDFLOW_HTTP_HOST}:${CHILDFLOW_HTTP_PORT}/"
  /bin/busybox httpd -f -p "${CHILDFLOW_HTTP_HOST}:${CHILDFLOW_HTTP_PORT}" -h "$root_dir" \
    >"$base_dir/httpd.stdout.log" 2>"$base_dir/httpd.stderr.log" &
  server_pid="$!"
  sleep 1
  if ! /bin/busybox wget -T 2 -q -O - "${CHILDFLOW_HTTP_TARGET}" >/dev/null 2>&1; then
    echo "error: local HTTP server probe failed for ${CHILDFLOW_HTTP_TARGET}" >&2
    echo "see $base_dir/httpd.stderr.log for server-side details" >&2
    exit 1
  fi
}

monitor_childflow() {
  local pid="$1"
  local flow_log_path="$2"
  local capture_path="$3"
  local metrics_path="$4"

  while kill -0 "$pid" >/dev/null 2>&1; do
    {
      printf 'ts=%s ' "$(date +%s)"
      if [[ -r "/proc/$pid/status" ]]; then
        awk '
          /^VmRSS:/ {rss_kib=$2}
          /^VmSize:/ {vmsize_kib=$2}
          END {
            printf "rss_kib=%s vmsize_kib=%s ", rss_kib ? rss_kib : 0, vmsize_kib ? vmsize_kib : 0
          }
        ' "/proc/$pid/status"
      else
        printf 'rss_kib=0 vmsize_kib=0 '
      fi
      if [[ -n "$flow_log_path" && -f "$flow_log_path" ]]; then
        printf 'flow_log_bytes=%s flow_log_lines=%s ' \
          "$(stat -c '%s' "$flow_log_path")" \
          "$(wc -l <"$flow_log_path")"
      else
        printf 'flow_log_bytes=0 flow_log_lines=0 '
      fi
      if [[ -n "$capture_path" && -f "$capture_path" ]]; then
        printf 'capture_bytes=%s ' "$(stat -c '%s' "$capture_path")"
      else
        printf 'capture_bytes=0 '
      fi
      printf '\n'
    } >>"$metrics_path"
    sleep "$CHILDFLOW_MONITOR_SEC"
  done
}

build_childflow_args() {
  local run_dir="$1"
  local -n out_args_ref="$2"
  out_args_ref=()

  case "$MODE" in
    both)
      out_args_ref+=(--flow-log "$run_dir/flow.jsonl" -c "$run_dir/capture.pcapng")
      ;;
    capture)
      out_args_ref+=(-c "$run_dir/capture.pcapng")
      ;;
    flow-log)
      out_args_ref+=(--flow-log "$run_dir/flow.jsonl")
      ;;
    none)
      ;;
    *)
      echo "error: unsupported mode '$MODE'" >&2
      exit 1
      ;;
  esac
}

run_case() {
  local case_name="$1"
  local command_text="$2"
  local run_dir="$base_dir/$case_name"
  local stdout_path="$run_dir/stdout.log"
  local stderr_path="$run_dir/stderr.log"
  local metrics_path="$run_dir/metrics.log"
  local flow_log_path=""
  local capture_path=""
  local -a childflow_args
  local -a backend_args

  mkdir -p "$run_dir"
  build_childflow_args "$run_dir" childflow_args

  if [[ -f "$run_dir/flow.jsonl" ]]; then
    flow_log_path="$run_dir/flow.jsonl"
  elif [[ " ${childflow_args[*]} " == *" --flow-log "* ]]; then
    flow_log_path="$run_dir/flow.jsonl"
  fi
  if [[ -f "$run_dir/capture.pcapng" ]]; then
    capture_path="$run_dir/capture.pcapng"
  elif [[ " ${childflow_args[*]} " == *" -c "* ]]; then
    capture_path="$run_dir/capture.pcapng"
  fi

  printf '%s\n' "$command_text" >"$run_dir/command.sh"
  printf 'scenario=%s\nmode=%s\nduration=%s\n' "$SCENARIO" "$MODE" "$DURATION" >"$run_dir/meta.txt"
  if [[ -n "$CHILDFLOW_HTTP_TARGET" ]]; then
    printf 'http_target=%s\n' "$CHILDFLOW_HTTP_TARGET" >>"$run_dir/meta.txt"
  fi

  read -r -a backend_args <<<"$CHILDFLOW_BACKEND_ARGS"
  {
    printf '%q ' "$CHILDFLOW_BIN"
    if [[ ${#backend_args[@]} -gt 0 ]]; then
      printf '%q ' "${backend_args[@]}"
    fi
    if [[ ${#childflow_args[@]} -gt 0 ]]; then
      printf '%q ' "${childflow_args[@]}"
    fi
    printf -- '-- bash -lc %q\n' "$command_text"
  } >"$run_dir/childflow.argv"
  "$CHILDFLOW_BIN" \
    "${backend_args[@]}" \
    "${childflow_args[@]}" \
    -- \
    bash -lc "$command_text" \
    >"$stdout_path" 2>"$stderr_path" &
  local childflow_pid="$!"

  monitor_childflow "$childflow_pid" "$flow_log_path" "$capture_path" "$metrics_path" &
  monitor_pid="$!"

  local rc=0
  wait "$childflow_pid" || rc=$?
  wait "$monitor_pid" || true
  monitor_pid=""

  {
    printf 'exit_code=%s\n' "$rc"
    [[ -f "$flow_log_path" ]] && printf 'flow_log_bytes=%s\n' "$(stat -c '%s' "$flow_log_path")"
    [[ -f "$flow_log_path" ]] && printf 'flow_log_lines=%s\n' "$(wc -l <"$flow_log_path")"
    [[ -f "$capture_path" ]] && printf 'capture_bytes=%s\n' "$(stat -c '%s' "$capture_path")"
  } >>"$run_dir/meta.txt"

  if [[ -x "$SUMMARY_SCRIPT" && -f "$metrics_path" ]]; then
    "$SUMMARY_SCRIPT" "$run_dir" >"$run_dir/summary.txt"
  fi

  if [[ -n "$flow_log_path" && ! -s "$flow_log_path" ]]; then
    echo "warning: flow log is empty: $flow_log_path" >&2
    echo "warning: childflow exit_code=$rc stderr follows" >&2
    sed -n '1,120p' "$stderr_path" >&2 || true
  fi

  echo "completed $case_name -> $run_dir"
  if [[ -f "$run_dir/summary.txt" ]]; then
    echo "summary: $run_dir/summary.txt"
  fi
}

steady_http_command() {
  cat <<EOF
end=\$((SECONDS + ${DURATION}))
while (( SECONDS < end )); do
  /bin/busybox wget -q -O - "${CHILDFLOW_HTTP_TARGET}" >/dev/null 2>&1 || true
  sleep "${CHILDFLOW_INTERVAL}"
done
EOF
}

short_tcp_command() {
  cat <<EOF
end=\$((SECONDS + ${DURATION}))
worker() {
  while (( SECONDS < end )); do
    /bin/busybox wget -q -O - "${CHILDFLOW_HTTP_TARGET}" >/dev/null 2>&1 || true
  done
}
i=0
while (( i < ${CHILDFLOW_WORKERS} )); do
  worker &
  i=\$((i + 1))
done
wait
EOF
}

dns_unique_command() {
  cat <<EOF
end=\$((SECONDS + ${DURATION}))
i=0
while (( SECONDS < end )); do
  host="load-\${i}.example.invalid"
  /bin/busybox wget -T 2 -q -O - "http://\${host}/" >/dev/null 2>&1 || true
  i=\$((i + 1))
  sleep "${CHILDFLOW_INTERVAL}"
done
EOF
}

deny_domain_storm_command() {
  cat <<EOF
end=\$((SECONDS + ${DURATION}))
i=0
while (( SECONDS < end )); do
  host="load-\${i}.blocked.example.invalid"
  /bin/busybox wget -T 2 -q -O - "http://\${host}/" >/dev/null 2>&1 || true
  i=\$((i + 1))
  sleep "${CHILDFLOW_INTERVAL}"
done
EOF
}

run_compare_observability() {
  local original_mode="$MODE"
  start_http_server
  MODE="capture"
  run_case capture-only "$(steady_http_command)"
  MODE="flow-log"
  run_case flow-log-only "$(steady_http_command)"
  MODE="both"
  run_case both "$(steady_http_command)"
  MODE="$original_mode"
}

case "$SCENARIO" in
  steady-http)
    start_http_server
    run_case steady-http "$(steady_http_command)"
    ;;
  short-tcp)
    start_http_server
    run_case short-tcp "$(short_tcp_command)"
    ;;
  dns-unique)
    run_case dns-unique "$(dns_unique_command)"
    ;;
  deny-domain-storm)
    MODE="flow-log"
    CHILDFLOW_BACKEND_ARGS="${CHILDFLOW_BACKEND_ARGS} --deny-domain example.invalid"
    run_case deny-domain-storm "$(deny_domain_storm_command)"
    ;;
  compare-observability)
    run_compare_observability
    ;;
  *)
    echo "error: unknown scenario '$SCENARIO'" >&2
    usage
    exit 1
    ;;
esac

echo "artifacts: $base_dir"
