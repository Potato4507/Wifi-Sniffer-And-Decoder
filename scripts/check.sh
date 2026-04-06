#!/usr/bin/env bash
set -euo pipefail

# Repo-root-aware check helper.
# It uses the local venv when available and auto-installs missing Python
# requirements for tests from the local package extras (.[dev]).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
NO_COMPILE=0

usage() {
    cat <<'EOF'
Usage: bash ./scripts/check.sh [--no-compile] [--help]

Options:
  --no-compile  Skip the compileall check
  --help        Show this message
EOF
}

for arg in "$@"; do
    case "$arg" in
        --no-compile) NO_COMPILE=1 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

if [[ ! -x "$PYTHON_BIN" ]]; then
    PYTHON_BIN="${PYTHON:-python3}"
fi

cd "$REPO_ROOT"

if ! "$PYTHON_BIN" -c "import pytest, build, numpy, scapy" >/dev/null 2>&1; then
    echo "[*] Installing Python check dependencies..."
    "$PYTHON_BIN" -m pip install -q -e ".[dev]"
fi

if [[ "$NO_COMPILE" -eq 0 ]]; then
    "$PYTHON_BIN" -m compileall -q wifi_pipeline
fi

"$PYTHON_BIN" -m pytest -q
