#!/usr/bin/env bash
# Build superset-query on macOS → dist/mac/superset-query
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script is for macOS only. Use ./py/build.sh on Linux." >&2
  exit 1
fi

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" &>/dev/null; then
  PYTHON=python
  if ! command -v "$PYTHON" &>/dev/null; then
    echo "Python not found. Install Python 3 from https://www.python.org/ or brew install python" >&2
    exit 1
  fi
fi

echo "Using: $($PYTHON --version 2>&1)"

echo "Installing/checking dependencies..."
"$PYTHON" -m pip install pyinstaller requests cryptography keyring

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "Building dist/mac/superset-query ..."
"$PYTHON" -m PyInstaller --noconfirm \
  --distpath "$ROOT/dist/mac" \
  --workpath "$ROOT/build/superset-query" \
  superset-query.spec

chmod +x "$ROOT/dist/mac/superset-query"

# Unsigned binaries may inherit quarantine xattr; strip so Gatekeeper allows execution.
xattr -cr "$ROOT/dist/mac/superset-query" 2>/dev/null || true
