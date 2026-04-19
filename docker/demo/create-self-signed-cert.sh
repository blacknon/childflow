#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <common-name> <cert-path> <key-path>" >&2
    exit 1
fi

common_name="$1"
cert_path="$2"
key_path="$3"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -keyout "$key_path" \
    -out "$cert_path" \
    -days 1 \
    -subj "/CN=${common_name}" \
    -addext "subjectAltName=DNS:${common_name}"
