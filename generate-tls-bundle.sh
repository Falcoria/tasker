#!/bin/bash

set -e

OUT_DIR=${1:-unit}
mkdir -p "$OUT_DIR"

CERT="$OUT_DIR/cert.pem"
KEY="$OUT_DIR/key.pem"
BUNDLE="$OUT_DIR/bundle.pem"

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$KEY" \
  -out "$CERT" \
  -days 365 \
  -subj "/CN=scanledger"

cat "$CERT" "$KEY" > "$BUNDLE"

echo "Generated TLS bundle at $BUNDLE"
