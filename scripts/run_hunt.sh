#!/usr/bin/env bash
# scripts/run_hunt.sh — thin wrapper around pipeline/run_hunt.py.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
python3 pipeline/run_hunt.py "$@"
