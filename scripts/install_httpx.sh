#!/usr/bin/env bash
# scripts/install_httpx.sh — installs ProjectDiscovery's httpx binary
# (tech-detect), NOT the Python httpx library.
set -euo pipefail
VERSION="1.6.9"
ARCH="linux_amd64"
URL="https://github.com/projectdiscovery/httpx/releases/download/v${VERSION}/httpx_${VERSION}_${ARCH}.zip"

TMP="$(mktemp -d)"
curl -sSL "$URL" -o "$TMP/httpx.zip"
unzip -q "$TMP/httpx.zip" -d "$TMP"
sudo mv "$TMP/httpx" /usr/local/bin/httpx
sudo chmod +x /usr/local/bin/httpx
rm -rf "$TMP"
httpx -version
