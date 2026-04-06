#!/usr/bin/env bash
set -euo pipefail

# Linux-first standalone validation helper.
# It auto-installs missing supported dependencies before running.
# Examples:
#   ./validate_local.sh --interface wlan0
#   sudo ./validate_local.sh --interface wlan0 --duration 15
#   ./validate_local.sh --no-install-deps --skip-smoke

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
source "$REPO_ROOT/scripts/common.sh"

INSTALL_MODE="auto"
CONFIG_PATH=""
INTERFACE=""
DURATION=""
REPORT=""
SKIP_SMOKE=0

usage() {
    cat <<'EOF'
Usage: ./validate_local.sh [options]

Options:
  --config <path>        Use a non-default config file
  --interface <name>     Override the local capture interface
  --duration <seconds>   Override smoke-capture duration
  --report <path>        Write the validation report to a custom path
  --skip-smoke           Run readiness checks only
  --install-deps         Force the installer to run even if deps look ready
  --no-install-deps      Skip the auto-installer check
  --help                 Show this message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-deps)
            INSTALL_MODE="force"
            ;;
        --no-install-deps)
            INSTALL_MODE="skip"
            ;;
        --config)
            CONFIG_PATH="${2:-}"
            shift
            ;;
        --interface)
            INTERFACE="${2:-}"
            shift
            ;;
        --duration)
            DURATION="${2:-}"
            shift
            ;;
        --report)
            REPORT="${2:-}"
            shift
            ;;
        --skip-smoke)
            SKIP_SMOKE=1
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown argument: %s\n' "$1" >&2
            exit 1
            ;;
    esac
    shift
done

ensure_repo_install_deps "$REPO_ROOT" "$INSTALL_MODE"

args=(validate-local)
if [[ -n "$INTERFACE" ]]; then
    args+=(--interface "$INTERFACE")
fi
if [[ -n "$DURATION" ]]; then
    args+=(--duration "$DURATION")
fi
if [[ -n "$REPORT" ]]; then
    args+=(--report "$REPORT")
fi
if [[ "$SKIP_SMOKE" -eq 1 ]]; then
    args+=(--skip-smoke)
fi

invoke_repo_pipeline "$REPO_ROOT" "$CONFIG_PATH" "${args[@]}"
