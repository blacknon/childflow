#!/usr/bin/env bash
set -euo pipefail

repo_root="/workspaces/childflow"
cd "$repo_root"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/childflow-target}"
export CHROME_PATH="${CHROME_PATH:-/usr/bin/chromium}"
mkdir -p "$CARGO_TARGET_DIR"

./docker/demo/wait-for-port.sh proxy-http 3128
./docker/demo/wait-for-port.sh proxy-https 3443

echo "[gif] building childflow"
cargo build

mkdir -p "$repo_root/img"

echo "[gif] rendering proxy demo gif"
vhs "$repo_root/docker/demo/tapes/proxy-demo.tape"

echo "[gif] rendered: $repo_root/img/childflow-proxy-demo.gif"
