#!/usr/bin/env bash
set -euo pipefail

# Linux-first day-to-day helper for standalone capture + analysis.
# It auto-installs missing supported dependencies before running.
# Examples:
#   ./run_local.sh
#   ./run_local.sh --pcap ./captures/input.pcapng
#   ./run_local.sh --validate-first --interface wlan0
#   ./run_local.sh --no-install-deps

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
source "$REPO_ROOT/scripts/common.sh"

INSTALL_MODE="auto"
CONFIG_PATH=""
PCAP_PATH=""
DECRYPTED_DIR=""
STRIP_WIFI=0
VALIDATE_FIRST=0
INTERFACE=""
DURATION=""

usage() {
    cat <<'EOF'
Usage: ./run_local.sh [options]

Options:
  --config <path>        Use a non-default config file
  --pcap <path>          Skip live capture and process an existing pcap
  --decrypted <dir>      Supply decrypted reference material
  --strip-wifi           Run Wi-Fi layer stripping before extraction
  --validate-first       Run standalone validation checks before the main flow
  --interface <name>     Override the capture interface for validation
  --duration <seconds>   Override validation duration for --validate-first
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
        --pcap)
            PCAP_PATH="${2:-}"
            shift
            ;;
        --decrypted)
            DECRYPTED_DIR="${2:-}"
            shift
            ;;
        --strip-wifi)
            STRIP_WIFI=1
            ;;
        --validate-first)
            VALIDATE_FIRST=1
            ;;
        --interface)
            INTERFACE="${2:-}"
            shift
            ;;
        --duration)
            DURATION="${2:-}"
            shift
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

if [[ "$VALIDATE_FIRST" -eq 1 ]]; then
    validate_args=(validate-local --skip-smoke)
    if [[ -n "$INTERFACE" ]]; then
        validate_args+=(--interface "$INTERFACE")
    fi
    if [[ -n "$DURATION" ]]; then
        validate_args+=(--duration "$DURATION")
    fi
    invoke_repo_pipeline "$REPO_ROOT" "$CONFIG_PATH" "${validate_args[@]}"
fi

run_args=(all)
if [[ -n "$PCAP_PATH" ]]; then
    run_args+=(--pcap "$PCAP_PATH")
fi
if [[ -n "$DECRYPTED_DIR" ]]; then
    run_args+=(--decrypted "$DECRYPTED_DIR")
fi
if [[ "$STRIP_WIFI" -eq 1 ]]; then
    run_args+=(--strip-wifi)
fi

invoke_repo_pipeline "$REPO_ROOT" "$CONFIG_PATH" "${run_args[@]}"
