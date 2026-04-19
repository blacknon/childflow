#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <host> <port>" >&2
    exit 1
fi

host="$1"
port="$2"

for _ in $(seq 1 60); do
    if bash -c "exec 3<>/dev/tcp/${host}/${port}" >/dev/null 2>&1; then
        exit 0
    fi
    sleep 1
done

echo "timed out waiting for ${host}:${port}" >&2
exit 1
