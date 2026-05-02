#!/usr/bin/env bash
set -euo pipefail

repo_root="/workspaces/childflow"
cd "$repo_root"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/childflow-target}"
export CHROME_PATH="${CHROME_PATH:-/usr/bin/chromium}"
mkdir -p "$CARGO_TARGET_DIR"

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

./docker/demo/wait-for-port.sh proxy-http 3128
./docker/demo/wait-for-port.sh proxy-https 3443

echo "[gif] building childflow"
cargo build

mkdir -p "$repo_root/img"
prepare_demo_artifact_dirs

render_tape() {
  local tape_path="$1"
  local rendered_path="$2"

  echo "[gif] rendering $(basename "$tape_path")"
  vhs "$tape_path"
  if [[ -f "$rendered_path" ]]; then
    echo "[gif] rendered: $rendered_path"
  fi
}

render_tape "$repo_root/docker/demo/tapes/proxy-demo.tape" \
  "$repo_root/img/childflow.gif"
cp "$repo_root/img/childflow.gif" "$repo_root/img/childflow-proxy-demo.gif"
echo "[gif] copied: $repo_root/img/childflow-proxy-demo.gif"

render_tape "$repo_root/docker/demo/tapes/profile-demo.tape" \
  "$repo_root/img/childflow-profile-demo.gif"
render_tape "$repo_root/docker/demo/tapes/flow-log-demo.tape" \
  "$repo_root/img/childflow-flow-log-demo.gif"
