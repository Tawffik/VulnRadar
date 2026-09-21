#!/usr/bin/env bash
# scripts/install_subfinder.sh — ProjectDiscovery subfinder (passive subdomain discovery)
set -euo pipefail
VERSION="2.6.7"
URL="https://github.com/projectdiscovery/subfinder/releases/download/v${VERSION}/subfinder_${VERSION}_linux_amd64.zip"
TMP="$(mktemp -d)"
curl -sSL "$URL" -o "$TMP/sf.zip"
unzip -q "$TMP/sf.zip" -d "$TMP"
sudo mv "$TMP/subfinder" /usr/local/bin/subfinder
sudo chmod +x /usr/local/bin/subfinder
rm -rf "$TMP"
subfinder -version
