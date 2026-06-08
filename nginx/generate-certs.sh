#!/bin/bash
set -euo pipefail

CERT_DIR="$(dirname "$0")/certs"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/scanboy.crt" ] && [ -f "$CERT_DIR/scanboy.key" ]; then
    echo "Certificates already exist. Remove them to regenerate."
    exit 0
fi

openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/scanboy.key" \
    -out "$CERT_DIR/scanboy.crt" \
    -subj "/C=US/ST=Local/L=Local/O=ScanBoy/OU=Security/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:scanboy.local,DNS:fraudvault.local,IP:127.0.0.1"

chmod 600 "$CERT_DIR/scanboy.key"
chmod 644 "$CERT_DIR/scanboy.crt"

echo "Self-signed certificates generated in $CERT_DIR"
