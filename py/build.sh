#!/usr/bin/env bash
# Build superset-query → dist/linux/superset-query
set -euo pipefail

echo "Installing/checking dependencies..."
python -m pip install -q pyinstaller requests cryptography keyring

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "Building dist/linux/superset-query ..."
python -m PyInstaller --noconfirm \
  --distpath "$ROOT/dist/linux" \
  --workpath "$ROOT/build/superset-query" \
  superset-query.spec

chmod +x "$ROOT/dist/linux/superset-query"
