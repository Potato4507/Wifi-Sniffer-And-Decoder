# Wifi-Sniffer-And-Decoder

Version 3.0 — dual-platform pipeline supporting native Windows capture and Linux/Kali monitor-mode capture with integrated WPA2 cracking.

---

## Platforms

| Feature | Windows | Linux / Kali |
|---|---|---|
| dumpcap / NPcap capture | ✅ | ❌ |
| Monitor mode (airmon-ng) | ❌ | ✅ |
| Handshake capture (airodump-ng / besside-ng) | ❌ | ✅ |
| WPA2 crack (aircrack-ng / hashcat) | ❌ | ✅ |
| airdecap-ng Wi-Fi strip | ✅ (bundle) | ✅ |
| Stream extraction / analysis / playback | ✅ | ✅ |

---

## Setup — Windows

```powershell
.\install_deps.ps1
.\.venv\Scripts\Activate.ps1
python .\videopipeline.py config
python .\videopipeline.py deps
```

To install Wireshark and FFmpeg automatically with `winget`:

```powershell
.\install_deps.ps1 -InstallWingetPackages
```

For Wi-Fi layer stripping on Windows, install the Windows aircrack-ng bundle and add `airdecap-ng` to PATH.

---

## Setup — Linux / Kali

```bash
sudo apt update
sudo apt install aircrack-ng hashcat hcxtools tcpdump python3-pip
pip install -r requirements.txt
sudo python3 videopipeline.py config
sudo python3 videopipeline.py deps
```

> Monitor mode and handshake capture require root (`sudo`).

---

## Commands

### Both platforms

```powershell
python .\videopipeline.py                    # Guided interactive menu
python .\videopipeline.py menu               # Same as above
python .\videopipeline.py web                # Browser dashboard  http://127.0.0.1:8765/
python .\videopipeline.py config             # Interactive configuration wizard
python .\videopipeline.py deps               # Check environment tools
python .\videopipeline.py corpus             # Show archived candidate streams
```

### Windows capture pipeline

```powershell
python .\videopipeline.py capture
python .\videopipeline.py capture --strip-wifi
python .\videopipeline.py extract --pcap .\pipeline_output\raw_capture.pcapng
python .\videopipeline.py detect
python .\videopipeline.py analyze --decrypted .\known_plaintext
python .\videopipeline.py play
python .\videopipeline.py all
python .\videopipeline.py all --strip-wifi
```

### Linux / Kali monitor-mode pipeline

```bash
# Step-by-step
sudo python3 videopipeline.py monitor                        # enable monitor mode + capture handshake
sudo python3 videopipeline.py monitor --method besside       # automatic multi-AP sweep
sudo python3 videopipeline.py monitor --method tcpdump       # generic raw 802.11 dump
sudo python3 videopipeline.py crack                          # crack PSK + airdecap-ng
sudo python3 videopipeline.py crack --cap ./hs.cap           # supply your own handshake

# Extract / detect / analyze as normal
sudo python3 videopipeline.py extract
sudo python3 videopipeline.py detect
sudo python3 videopipeline.py analyze
sudo python3 videopipeline.py play

# Full end-to-end in one command
sudo python3 videopipeline.py wifi
sudo python3 videopipeline.py wifi --method besside
```

---

## Configuration (lab.json)

Key fields added in v3:

| Key | Default | Purpose |
|---|---|---|
| `ap_bssid` | `""` | BSSID of target AP (required for airodump-ng) |
| `ap_channel` | `6` | Wi-Fi channel of target AP |
| `monitor_method` | `"airodump"` | `airodump` / `besside` / `tcpdump` |
| `wordlist_path` | `/usr/share/wordlists/rockyou.txt` | Dictionary for aircrack-ng / hashcat |
| `handshake_timeout` | `120` | Seconds to wait for handshake capture |
| `crack_timeout` | `600` | Seconds allowed for cracking |
| `deauth_count` | `10` | Deauth frames sent to force reconnect (`0` = passive) |
| `hashcat_rules` | `""` | Optional hashcat rules file path |

> **Never store your WPA password in lab.json.** Use the environment variable instead:
>
> ```bash
> export WIFI_PIPELINE_WPA_PASSWORD="yourpassword"
> ```

---

## What Changed in v3

- **IPv6 support** — extraction now handles IPv6 frames; the old `IP not in packet` guard is gone.
- **Non-TCP/UDP protocols** — ICMP, ICMPv6, SCTP, and GRE flows are now extracted and written as `raw_datagram` units.
- **Monitor-mode capture** — `airmon-ng` integration via the new `monitor` subcommand; puts the card into monitor mode to capture all frames on the air including third-party device traffic invisible to managed-mode captures.
- **Handshake capture** — `airodump-ng` (targeted) and `besside-ng` (automatic) wired into the pipeline.
- **WPA2 cracking** — aircrack-ng dictionary attack followed by hashcat PMKID/HCCAPX fallback; recovered PSK is fed directly into `airdecap-ng`.
- **`wifi` subcommand** — runs the full Linux pipeline end-to-end in one command.
- **Platform-aware environment check** — `deps` now shows the correct tool list for Windows or Linux.
- **`environment_model` no longer forced to `native_windows` on Linux.**
- **`run_extract` prefers the decrypted pcap** when it exists, so you don't have to pass `--pcap` explicitly after a `crack` run.
- Schema version bumped to 3 with `stream_stats` breakdown in the manifest.
