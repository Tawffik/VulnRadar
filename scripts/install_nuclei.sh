#!/usr/bin/env bash
# scripts/install_nuclei.sh — installs ProjectDiscovery's nuclei binary.
set -euo pipefail
VERSION="3.3.9"
ARCH="linux_amd64"
URL="https://github.com/projectdiscovery/nuclei/releases/download/v${VERSION}/nuclei_${VERSION}_${ARCH}.zip"

TMP="$(mktemp -d)"
curl -sSL "$URL" -o "$TMP/nuclei.zip"
unzip -q "$TMP/nuclei.zip" -d "$TMP"
sudo mv "$TMP/nuclei" /usr/local/bin/nuclei
sudo chmod +x /usr/local/bin/nuclei
rm -rf "$TMP"
nuclei -version
