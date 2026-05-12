#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  docker/dev/summarize-load-test.sh <run-dir-or-metrics.log>

Examples:
  docker/dev/summarize-load-test.sh /tmp/childflow-loadtest/steady-http-20260510-114421/steady-http
  docker/dev/summarize-load-test.sh /tmp/childflow-loadtest/steady-http-20260510-114421/steady-http/metrics.log
EOF
}

if [[ "${1:-}" == "" || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

input="$1"
run_dir=""
metrics_path=""

if [[ -d "$input" ]]; then
  run_dir="$input"
  metrics_path="$run_dir/metrics.log"
elif [[ -f "$input" ]]; then
  metrics_path="$input"
  run_dir="$(dirname "$metrics_path")"
else
  echo "error: input not found: $input" >&2
  exit 1
fi

if [[ ! -f "$metrics_path" ]]; then
  echo "error: metrics log not found: $metrics_path" >&2
  exit 1
fi

awk '
function rate(delta, duration) {
  if (duration <= 0) {
    return "0.00"
  }
  return sprintf("%.2f", delta / duration)
}

function growth_label(delta_kib) {
  if (delta_kib <= 256) {
    return "stable"
  }
  if (delta_kib <= 1024) {
    return "slight_growth"
  }
  return "growing"
}

BEGIN {
  samples = 0
}
{
  for (i = 1; i <= NF; i++) {
    split($i, kv, "=")
    key = kv[1]
    value = kv[2] + 0
    data[key] = value
  }

  samples++
  ts = data["ts"]
  rss = data["rss_kib"]
  vmsize = data["vmsize_kib"]
  flow_bytes = data["flow_log_bytes"]
  flow_lines = data["flow_log_lines"]
  capture_bytes = data["capture_bytes"]

  if (samples == 1) {
    first_ts = ts
    first_rss = rss
    first_vmsize = vmsize
    first_flow_bytes = flow_bytes
    first_flow_lines = flow_lines
    first_capture_bytes = capture_bytes
    max_rss = rss
    max_vmsize = vmsize
  }

  last_ts = ts
  last_rss = rss
  last_vmsize = vmsize
  last_flow_bytes = flow_bytes
  last_flow_lines = flow_lines
  last_capture_bytes = capture_bytes

  if (rss > max_rss) {
    max_rss = rss
  }
  if (vmsize > max_vmsize) {
    max_vmsize = vmsize
  }
}
END {
  duration = (samples > 1) ? (last_ts - first_ts) : 0
  rss_delta = last_rss - first_rss
  vmsize_delta = last_vmsize - first_vmsize
  flow_bytes_delta = last_flow_bytes - first_flow_bytes
  flow_lines_delta = last_flow_lines - first_flow_lines
  capture_bytes_delta = last_capture_bytes - first_capture_bytes

  printf "samples=%d\n", samples
  printf "observed_duration_sec=%d\n", duration
  printf "rss_kib_initial=%d\n", first_rss
  printf "rss_kib_final=%d\n", last_rss
  printf "rss_kib_max=%d\n", max_rss
  printf "rss_kib_delta=%d\n", rss_delta
  printf "rss_trend=%s\n", growth_label(rss_delta)
  printf "vmsize_kib_initial=%d\n", first_vmsize
  printf "vmsize_kib_final=%d\n", last_vmsize
  printf "vmsize_kib_max=%d\n", max_vmsize
  printf "vmsize_kib_delta=%d\n", vmsize_delta
  printf "flow_log_bytes_initial=%d\n", first_flow_bytes
  printf "flow_log_bytes_final=%d\n", last_flow_bytes
  printf "flow_log_bytes_delta=%d\n", flow_bytes_delta
  printf "flow_log_bytes_per_sec=%s\n", rate(flow_bytes_delta, duration)
  printf "flow_log_lines_initial=%d\n", first_flow_lines
  printf "flow_log_lines_final=%d\n", last_flow_lines
  printf "flow_log_lines_delta=%d\n", flow_lines_delta
  printf "flow_log_lines_per_sec=%s\n", rate(flow_lines_delta, duration)
  printf "capture_bytes_initial=%d\n", first_capture_bytes
  printf "capture_bytes_final=%d\n", last_capture_bytes
  printf "capture_bytes_delta=%d\n", capture_bytes_delta
  printf "capture_bytes_per_sec=%s\n", rate(capture_bytes_delta, duration)
}
' "$metrics_path"
