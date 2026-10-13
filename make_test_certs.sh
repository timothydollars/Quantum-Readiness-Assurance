#!/usr/bin/env bash
# Creates throw-away self-signed certificates for the PEM adapter tests.
# Run once from the repository root:  bash scripts/make_test_certs.sh
set -euo pipefail
out=tests/fixtures/certs
mkdir -p "$out"
openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -out "$out/rsa2048.pem" \
  -days 365 -subj "/CN=qraf-test-rsa" 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /dev/null \
  -out "$out/ecp256.pem" -days 365 -subj "/CN=qraf-test-ec" 2>/dev/null
echo "not a certificate" > "$out/notes.txt"
# ML-DSA certificates need OpenSSL 3.5 or later; skipped silently on older versions.
if openssl list -signature-algorithms 2>/dev/null | grep -qi "ML-DSA-65"; then
  openssl req -x509 -newkey ML-DSA-65 -nodes -keyout /dev/null -out "$out/mldsa65.pem" \
    -days 365 -subj "/CN=qraf-test-mldsa" 2>/dev/null
fi
ls -1 "$out"
