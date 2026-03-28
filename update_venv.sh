#!/usr/bin/env bash
# Rebuild the native C++ extension and install it into .venv
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/.venv/Scripts/python.exe"

if [[ ! -f "$VENV_PYTHON" ]]; then
    echo "Error: .venv not found at $SCRIPT_DIR/.venv" >&2
    exit 1
fi

echo "Building native extension..."
"$VENV_PYTHON" setup.py build_ext --inplace

# Find the built .pyd for the venv's Python version
PYD=$(find "$SCRIPT_DIR/build" -path "*/dotenv_webauthn_crypt/_webauthn.cp*-win_amd64.pyd" -newer "$SCRIPT_DIR/ext/_webauthn.cpp" | head -1)

if [[ -z "$PYD" ]]; then
    echo "Error: no freshly built .pyd found" >&2
    exit 1
fi

DEST="$SCRIPT_DIR/.venv/Lib/site-packages/dotenv_webauthn_crypt/$(basename "$PYD")"
cp "$PYD" "$DEST"
echo "Installed $(basename "$PYD") into .venv"
