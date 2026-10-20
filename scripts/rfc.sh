#!/usr/bin/env bash
# Download RFC texts for ACME implementation reference
# RFC 8555 - ACME Protocol
# RFC 9773 - ACME Renewal Information (ARI) Extension

set -euo pipefail

RFC_DIR="${1:-/home/randop/Projects/acme/rfc}"
mkdir -p "$RFC_DIR"

echo "Downloading RFC 8555 (ACME Protocol)..."
curl -fsSL "https://www.rfc-editor.org/rfc/rfc8555.txt" -o "$RFC_DIR/rfc8555.txt"

echo "Downloading RFC 9773 (ACME Renewal Information / ARI)..."
curl -fsSL "https://www.rfc-editor.org/rfc/rfc9773.txt" -o "$RFC_DIR/rfc9773.txt"

echo "Done. Files saved to $RFC_DIR/"
ls -la "$RFC_DIR/"