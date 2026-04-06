# install_deps.ps1
$ProjectWsl = "/mnt/c/Users/dwdow/OneDrive/Documents"

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    Write-Host "WSL is not installed."
    Write-Host "Run this in an ADMIN PowerShell first:"
    Write-Host "  wsl --install -d Ubuntu"
    exit 1
}

wsl bash -lc "
set -e
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt install -y \
    python3 python3-venv python3-pip \
    tcpdump aircrack-ng tshark ffmpeg

cd '$ProjectWsl'

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install numpy scapy

echo
echo 'Dependencies installed.'
echo 'Run the pipeline with:'
echo '  cd $ProjectWsl'
echo '  source .venv/bin/activate'
echo '  python3 videopipeline.py'
"
