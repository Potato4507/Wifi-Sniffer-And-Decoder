#!/usr/bin/env bash
# WiFi Stream Pipeline dependency installer.
# Primary use: prepare Ubuntu or Raspberry Pi OS for standalone use.
# Also usable to prepare a Linux box for Windows remote-capture workflows.
#
# Usage:
#   chmod +x install_deps.sh
#   ./install_deps.sh              # Install system packages + venv + Python deps
#   ./install_deps.sh --no-system  # Skip system packages
#   ./install_deps.sh --skip-ssh   # Do not create an SSH key
#   ./install_deps.sh --full       # Same as default (kept for compatibility)
#   ./install_deps.sh --help       # Show options

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FULL=1
SETUP_SSH=1

log() {
    printf '%s\n' "$*"
}

die() {
    printf '[!] %s\n' "$*" >&2
    exit 1
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

usage() {
    cat <<'EOF'
Usage: ./install_deps.sh [--no-system] [--skip-ssh] [--full] [--help]

Options:
  --no-system  Skip apt/Homebrew package installation
  --skip-ssh   Skip SSH key generation for remote capture pairing
  --full       Keep compatibility with older docs; same as the default behavior
  --help       Show this message

Notes:
  - The helper scripts auto-install missing supported dependencies by default.
  - Use ./setup_local.sh, ./run_local.sh, or ./validate_local.sh for the
    Linux-first supported path after this installer completes.
EOF
}

for arg in "$@"; do
    case "$arg" in
        --full) FULL=1 ;;
        --no-system) FULL=0 ;;
        --skip-ssh) SETUP_SSH=0 ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown argument: $arg" ;;
    esac
done

OS=""
LINUX_TARGET="best-effort-linux"
if [[ "$(uname -s)" == "Darwin" ]]; then
    OS="macos"
elif [[ -f /etc/os-release ]]; then
    OS="linux"
else
    die "Unsupported platform: $(uname -s)"
fi

log "[*] Detected platform: $OS"
log "[*] Official product modes:"
log "    - Ubuntu standalone"
log "    - Raspberry Pi OS standalone"
log "    - Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture"
log "[*] Explicit limits:"
log "    - This project does not make Windows monitor mode adapter-independent"
log "    - Only Ubuntu and Raspberry Pi OS are officially supported Linux targets"
log "    - Replay and payload reconstruction remain heuristic"

if [[ "$OS" == "linux" && -f /etc/os-release ]]; then
    # We keep the supported Linux story intentionally narrow so standalone mode
    # feels reliable instead of vaguely portable.
    . /etc/os-release
    case "${ID:-}" in
        ubuntu)
            LINUX_TARGET="ubuntu"
            ;;
        raspbian)
            LINUX_TARGET="raspberry-pi-os"
            ;;
        debian)
            if [[ "${NAME:-}" == *"Raspberry Pi"* ]]; then
                LINUX_TARGET="raspberry-pi-os"
            fi
            ;;
    esac
fi

if [[ "$OS" == "linux" ]]; then
    case "$LINUX_TARGET" in
        ubuntu)
            log "[*] Installer profile: Ubuntu standalone (official)"
            ;;
        raspberry-pi-os)
            log "[*] Installer profile: Raspberry Pi OS standalone (official)"
            ;;
        *)
            log "[!] Installer profile: other Linux distro (best effort only)"
            ;;
    esac
fi

if [[ "$FULL" -eq 1 ]]; then
    if [[ "$OS" == "linux" ]]; then
        if ! have_cmd apt-get; then
            log "[!] Automatic system package installation currently targets apt-based Ubuntu and Raspberry Pi OS systems."
            log "[!] Skipping system package installation on this distro."
        else
            log "[*] Installing system packages via apt ..."
            sudo apt-get update -qq
            sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
                aircrack-ng \
                hashcat \
                hcxtools \
                openssh-client \
                tcpdump \
                wireshark \
                tshark \
                ffmpeg \
                python3-pip \
                python3-venv
            log "[+] System packages installed."
        fi
    elif [[ "$OS" == "macos" ]]; then
        if ! have_cmd brew; then
            die "Homebrew not found. Install it from https://brew.sh then re-run."
        fi
        log "[*] Installing system packages via Homebrew ..."
        brew install aircrack-ng hashcat hcxtools ffmpeg
        brew install --cask wireshark || true
        log "[+] System packages installed."
        log "[!] Note: tcpdump is built in on macOS. No extra install needed."
        log "[!] Monitor mode uses: sudo tcpdump -I -i <interface>"
    fi
else
    log "[*] Skipping system package install."
fi

if ! have_cmd python3; then
    die "python3 is required. Install Python 3.12+ and re-run this script."
fi

if [[ ! -d .venv ]]; then
    log "[*] Creating Python virtual environment in .venv ..."
    python3 -m venv .venv
    log "[+] Virtual environment created."
else
    log "[*] Virtual environment already exists at .venv; reusing."
fi

log "[*] Installing Python packages from requirements.txt ..."
source .venv/bin/activate
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet -r requirements.txt
log "[+] Python packages installed."

if [[ "$SETUP_SSH" -eq 1 ]]; then
    if have_cmd ssh-keygen; then
        mkdir -p "$HOME/.ssh"
        if [[ ! -f "$HOME/.ssh/id_ed25519" ]]; then
            log "[*] Generating SSH key for remote capture pairing ..."
            ssh-keygen -t ed25519 -f "$HOME/.ssh/id_ed25519" -N "" >/dev/null
            log "[+] SSH key created at $HOME/.ssh/id_ed25519.pub"
        else
            log "[*] SSH key already exists at $HOME/.ssh/id_ed25519"
        fi
    else
        log "[!] ssh-keygen not found; skipping SSH key setup."
    fi
fi

log ""
log "[+] Done. Activate the venv with:"
log "      source .venv/bin/activate"
log ""
if [[ "$OS" == "linux" ]]; then
log "    Standalone next steps on this Linux machine:"
log "      ./setup_local.sh"
log "      ./validate_local.sh --interface wlan0"
log "      ./run_local.sh"
log "      python3 videopipeline.py web"
log "      bash ./scripts/check.sh"
    log "    (The helper scripts auto-install missing supported dependencies by default.)"
    log ""
    log "    Raw CLI equivalents:"
    log "      python3 videopipeline.py deps"
    log "      python3 videopipeline.py config"
    log "      python3 videopipeline.py validate-local --interface wlan0"
    log "      python3 videopipeline.py all"
    log "      python3 videopipeline.py"
    log ""
    log "    Optional Wi-Fi lab steps if your adapter supports monitor mode:"
    log "      sudo python3 videopipeline.py monitor"
    log "      sudo python3 videopipeline.py wifi"
    log ""
    log "    If this Linux box will serve as a Windows capture appliance:"
    log "      install here with ./install_deps.sh"
    log "      then go back to the Windows controller and run:"
    log "      .\\setup_remote.ps1"
    log "      .\\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0"
    log "      .\\run_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -DoctorFirst"
else
    log "    Experimental macOS next steps:"
    log "      python3 videopipeline.py deps"
    log "      python3 videopipeline.py config"
    log "      python3 videopipeline.py extract --pcap /path/to/input.pcapng"
    log "      python3 videopipeline.py analyze"
    log "      bash ./scripts/check.sh"
fi

if [[ "$OS" == "linux" ]]; then
    log ""
    log "    Monitor mode and capture require root:"
    log "      sudo python3 videopipeline.py monitor"
    log "      sudo python3 videopipeline.py wifi"
    log "    Other Linux distributions may work, but Ubuntu and Raspberry Pi OS are the only officially supported Linux standalone targets."
elif [[ "$OS" == "macos" ]]; then
    log ""
    log "    Monitor mode (tcpdump -I) requires root:"
    log "      sudo python3 videopipeline.py monitor --method tcpdump"
    log "    macOS is a development/experimental path, not an officially supported target."
fi
