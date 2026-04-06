from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .ui import BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW, ask, confirm, err, info, ok, section, warn

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX   = sys.platform.startswith("linux")
IS_MACOS   = sys.platform == "darwin"

SUPPORTED_PRODUCT_MODES = (
    "Ubuntu standalone",
    "Raspberry Pi OS standalone",
    "Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture",
)
SUPPORTED_PRODUCT_SUMMARY = "; ".join(SUPPORTED_PRODUCT_MODES)


@dataclass
class ToolStatus:
    name: str
    purpose: str
    required: bool
    path: Optional[str]


@dataclass(frozen=True)
class ProductProfile:
    key: str
    label: str
    official: bool
    standalone: bool
    remote_capture: bool
    description: str


@dataclass(frozen=True)
class CommandSupport:
    command: str
    profile: ProductProfile
    status: str
    message: str


@dataclass(frozen=True)
class WorkflowSupport:
    area: str
    tier: str
    summary: str
    detail: str


@dataclass(frozen=True)
class HardwareCatalogEntry:
    family: str
    role: str
    status: str
    profiles: Tuple[str, ...]
    match_terms: Tuple[str, ...]
    monitor_mode: str
    injection: str
    channels: str
    detail: str


@dataclass(frozen=True)
class HardwareQualification:
    area: str
    label: str
    status: str
    summary: str
    detail: str
    monitor_mode: str
    injection: str
    channels: str


PRODUCT_PROFILES: Dict[str, ProductProfile] = {
    "ubuntu_standalone": ProductProfile(
        key="ubuntu_standalone",
        label="Ubuntu standalone",
        official=True,
        standalone=True,
        remote_capture=True,
        description="Full local capture and analysis on Ubuntu.",
    ),
    "pi_standalone": ProductProfile(
        key="pi_standalone",
        label="Raspberry Pi OS standalone",
        official=True,
        standalone=True,
        remote_capture=True,
        description="Full local capture and analysis on Raspberry Pi OS.",
    ),
    "windows_remote": ProductProfile(
        key="windows_remote",
        label="Windows 10/11 + Ubuntu/Raspberry Pi OS remote capture",
        official=True,
        standalone=False,
        remote_capture=True,
        description="Windows controls and analyzes while Linux handles capture.",
    ),
    "windows_experimental_local": ProductProfile(
        key="windows_experimental_local",
        label="Windows local capture (experimental)",
        official=False,
        standalone=False,
        remote_capture=False,
        description="Best-effort native Windows capture and Wi-Fi lab path.",
    ),
    "linux_best_effort": ProductProfile(
        key="linux_best_effort",
        label="Other Linux distro (best effort)",
        official=False,
        standalone=True,
        remote_capture=True,
        description="Linux workflow outside the official Ubuntu/Raspberry Pi OS targets.",
    ),
    "macos_experimental": ProductProfile(
        key="macos_experimental",
        label="macOS experimental",
        official=False,
        standalone=True,
        remote_capture=False,
        description="Experimental macOS workflow.",
    ),
}


SUPPORTED_HARDWARE_CATALOG: Tuple[HardwareCatalogEntry, ...] = (
    HardwareCatalogEntry(
        family="Atheros AR9271 / ath9k_htc",
        role="linux_capture_adapter",
        status="supported",
        profiles=("ubuntu_standalone", "pi_standalone", "linux_best_effort"),
        match_terms=("ath9k_htc", "ar9271", "qca9271", "atheros ar9271"),
        monitor_mode="qualified",
        injection="qualified",
        channels="2.4 GHz",
        detail="Best-supported USB adapter family for the full Linux Wi-Fi lab workflow.",
    ),
    HardwareCatalogEntry(
        family="MediaTek MT7612U / mt76x2u",
        role="linux_capture_adapter",
        status="supported_with_limits",
        profiles=("ubuntu_standalone", "pi_standalone", "linux_best_effort"),
        match_terms=("mt76x2u", "mt7612u"),
        monitor_mode="qualified",
        injection="best effort",
        channels="2.4/5 GHz",
        detail="Good dual-band Linux capture option, but injection and firmware behavior still vary by device.",
    ),
    HardwareCatalogEntry(
        family="Ralink/MediaTek RT5572 / rt2800usb",
        role="linux_capture_adapter",
        status="supported_with_limits",
        profiles=("ubuntu_standalone", "pi_standalone", "linux_best_effort"),
        match_terms=("rt2800usb", "rt5572"),
        monitor_mode="qualified",
        injection="best effort",
        channels="2.4/5 GHz",
        detail="Common dual-band USB capture option; keep expectations conservative for injection-heavy lab steps.",
    ),
    HardwareCatalogEntry(
        family="Intel iwlwifi family",
        role="linux_capture_adapter",
        status="supported_with_limits",
        profiles=("ubuntu_standalone", "linux_best_effort"),
        match_terms=("iwlwifi", "intel wireless", "intel corporation wifi"),
        monitor_mode="available on many chipsets",
        injection="not part of the qualified lab path",
        channels="chipset dependent",
        detail="Useful for pcap-first and sniffing workflows, but not the narrow recommended adapter family for full Wi-Fi lab work.",
    ),
    HardwareCatalogEntry(
        family="Broadcom brcmfmac family",
        role="linux_capture_adapter",
        status="unsupported",
        profiles=("ubuntu_standalone", "pi_standalone", "linux_best_effort"),
        match_terms=("brcmfmac", "broadcom"),
        monitor_mode="limited / chipset dependent",
        injection="not qualified",
        channels="chipset dependent",
        detail="Typical onboard Broadcom Raspberry Pi radios are not part of the qualified monitor/injection hardware program.",
    ),
)


# Tools required/optional on Windows
WINDOWS_TOOLS = (
    ("dumpcap",      "Packet capture through NPcap/Wireshark",  True),
    ("tshark",       "Packet parsing and inspection",           True),
    ("WlanHelper",   "Npcap Wi-Fi mode helper (monitor/managed)", False),
    ("ffplay",       "Optional playback preview",               False),
    ("airdecap-ng",  "Wi-Fi layer decryption (aircrack-ng)",   False),
    ("aircrack-ng",  "WPA2 handshake capture and cracking",     False),
    ("airodump-ng",  "Targeted WPA2 handshake capture",         False),
    ("aireplay-ng",  "Deauth frames for faster handshake",      False),
    ("besside-ng",   "Automatic multi-AP handshake capture",    False),
    ("hashcat",      "GPU-accelerated WPA2 crack",             False),
)

# Tools required/optional on Linux / Kali
LINUX_TOOLS = (
    ("airmon-ng",    "Enable/disable monitor mode",             True),
    ("airodump-ng",  "Targeted WPA2 handshake capture",         True),
    ("aireplay-ng",  "Deauth frames for faster handshake",      False),
    ("aircrack-ng",  "WPA2 PSK dictionary crack",               True),
    ("besside-ng",   "Automatic multi-AP handshake capture",    False),
    ("airdecap-ng",  "Strip Wi-Fi layer from pcap",             True),
    ("hashcat",      "GPU-accelerated WPA2 crack (optional)",   False),
    ("cap2hccapx",   "Convert .cap to hashcat format",          False),
    ("hcxpcapngtool","Alternative cap converter (hcxtools)",    False),
    ("tcpdump",      "Generic monitor-mode raw capture",        False),
    ("ffplay",       "Optional playback preview",               False),
)

# Tools required/optional on macOS
# Install via: brew install aircrack-ng hashcat hcxtools wireshark
# tcpdump ships with macOS and supports monitor mode via -I flag.
MACOS_TOOLS = (
    ("tcpdump",      "Raw capture + monitor mode (-I flag, built-in)", True),
    ("dumpcap",      "Packet capture via Wireshark (brew --cask wireshark)", False),
    ("tshark",       "Packet parsing (brew install wireshark)",        False),
    ("aircrack-ng",  "WPA2 PSK dictionary crack (brew install aircrack-ng)", True),
    ("airdecap-ng",  "Strip Wi-Fi layer from pcap (included with aircrack-ng)", True),
    ("besside-ng",   "Automatic multi-AP handshake capture",           False),
    ("hashcat",      "GPU-accelerated WPA2 crack (brew install hashcat)", False),
    ("cap2hccapx",   "Convert .cap to hashcat format (brew install hcxtools)", False),
    ("hcxpcapngtool","Alternative cap converter (brew install hcxtools)", False),
    ("ffplay",       "Optional playback preview (brew install ffmpeg)", False),
)

def _find_windows_wlanhelper() -> Optional[str]:
    if not IS_WINDOWS:
        return None

    for name in ("WlanHelper.exe", "WlanHelper"):
        found = shutil.which(name)
        if found:
            return found

    system_root = os.environ.get("SYSTEMROOT") or os.environ.get("SystemRoot") or r"C:\Windows"
    candidates = [
        os.path.join(system_root, "System32", "Npcap", "WlanHelper.exe"),
        os.path.join(system_root, "Sysnative", "Npcap", "WlanHelper.exe"),
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Npcap", "WlanHelper.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Npcap", "WlanHelper.exe"),
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate

    return None


def _tool_path(name: str) -> Optional[str]:
    if IS_WINDOWS and name.lower().startswith("wlanhelper"):
        return _find_windows_wlanhelper()
    return shutil.which(name)


def _tool_available(name: str) -> bool:
    return bool(_tool_path(name))


def _tier_sort_key(tier: str) -> int:
    order = {
        "supported": 0,
        "supported_with_limits": 1,
        "heuristic": 2,
        "unsupported": 3,
    }
    return order.get(tier, 99)


def _tier_label(tier: str) -> str:
    labels = {
        "supported": "supported",
        "supported_with_limits": "supported with limits",
        "heuristic": "heuristic",
        "unsupported": "unsupported",
    }
    return labels.get(tier, tier.replace("_", " "))


def _read_text_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _machine_architecture() -> str:
    return platform.machine().strip().lower() or "unknown"


def _linux_interface_driver(interface: str) -> str:
    if not IS_LINUX or not interface:
        return ""

    uevent_path = os.path.join("/sys/class/net", interface, "device", "uevent")
    if os.path.exists(uevent_path):
        for raw_line in _read_text_file(uevent_path).splitlines():
            if raw_line.startswith("DRIVER="):
                return raw_line.split("=", 1)[1].strip().lower()

    driver_link = os.path.join("/sys/class/net", interface, "device", "driver")
    if os.path.islink(driver_link):
        try:
            return os.path.basename(os.path.realpath(driver_link)).strip().lower()
        except OSError:
            return ""

    return ""


def _linux_interface_fingerprint(interface: str, description: str = "") -> str:
    if not IS_LINUX or not interface:
        return ""

    base = os.path.join("/sys/class/net", interface, "device")
    parts = [
        interface,
        description,
        _linux_interface_driver(interface),
        _read_text_file(os.path.join(base, "vendor")),
        _read_text_file(os.path.join(base, "device")),
        _read_text_file(os.path.join(base, "modalias")),
        _read_text_file(os.path.join(base, "uevent")),
    ]
    return " ".join(part.strip().lower() for part in parts if part and part.strip())


def _match_hardware_catalog(fingerprint: str, profile_key: str) -> Optional[HardwareCatalogEntry]:
    lowered = fingerprint.lower()
    for entry in SUPPORTED_HARDWARE_CATALOG:
        if profile_key not in entry.profiles:
            continue
        if any(term in lowered for term in entry.match_terms):
            return entry
    return None


def _read_os_release() -> Dict[str, str]:
    if not IS_LINUX:
        return {}
    path = "/etc/os-release"
    if not os.path.exists(path):
        return {}

    values: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def _linux_machine_model() -> str:
    if not IS_LINUX:
        return ""

    for path in ("/sys/firmware/devicetree/base/model", "/proc/device-tree/model"):
        if not os.path.exists(path):
            continue
        try:
            return open(path, "r", encoding="utf-8", errors="ignore").read().strip("\x00\r\n ")
        except OSError:
            return ""
    return ""


def linux_distribution_label() -> str:
    if not IS_LINUX:
        return ""

    data = _read_os_release()
    pretty = data.get("PRETTY_NAME") or data.get("NAME") or "Linux"
    model = _linux_machine_model()
    if "raspberry pi" in pretty.lower():
        return pretty
    if "raspberry pi" in model.lower():
        return f"{pretty} on Raspberry Pi".strip()
    return pretty


def default_product_mode() -> str:
    if IS_WINDOWS:
        return "windows_remote"
    if IS_MACOS:
        return "macos_experimental"
    if not IS_LINUX:
        return "macos_experimental"

    data = _read_os_release()
    distro_id = data.get("ID", "").strip().lower()
    pretty = (data.get("PRETTY_NAME") or data.get("NAME") or "").lower()
    model = _linux_machine_model().lower()
    if distro_id == "ubuntu":
        return "ubuntu_standalone"
    if distro_id == "raspbian" or "raspberry pi os" in pretty or "raspberry pi" in model:
        return "pi_standalone"
    return "linux_best_effort"


def resolve_product_profile(config: Optional[Dict[str, object]] = None) -> ProductProfile:
    requested = str((config or {}).get("product_mode") or "").strip().lower().replace("-", "_")
    detected_key = default_product_mode()

    if requested in PRODUCT_PROFILES:
        if IS_WINDOWS and requested in ("windows_remote", "windows_experimental_local"):
            return PRODUCT_PROFILES[requested]
        if IS_MACOS and requested == "macos_experimental":
            return PRODUCT_PROFILES[requested]
        if IS_LINUX and requested == detected_key:
            return PRODUCT_PROFILES[requested]

    return PRODUCT_PROFILES[detected_key]


def command_support(
    command: str,
    config: Optional[Dict[str, object]] = None,
    *,
    has_input_pcap: bool = False,
) -> CommandSupport:
    profile = resolve_product_profile(config)

    analysis_commands = {"config", "deps", "hardware", "preflight", "release-gate", "crack-status", "extract", "detect", "analyze", "play", "corpus", "web", "menu"}
    remote_commands = {"remote", "discover-remote", "pair-remote", "bootstrap-remote", "start-remote", "remote-service", "validate-remote", "setup-remote"}
    local_validation_commands = {"validate-local"}
    local_capture_commands = {"capture"}
    local_wifi_commands = {"monitor", "crack", "wifi"}

    if command == "all" and has_input_pcap:
        command = "extract"

    if command == "doctor":
        if profile.official:
            return CommandSupport(command, profile, "official", "")
        if profile.key == "linux_best_effort":
            return CommandSupport(command, profile, "best_effort", "Doctor runs outside the official support matrix on this Linux distro.")
        return CommandSupport(command, profile, "experimental", "Doctor remains available, but this platform is not part of an official product mode.")

    if command in analysis_commands:
        if profile.key == "macos_experimental":
            return CommandSupport(command, profile, "experimental", "macOS remains experimental, so analysis commands run in experimental mode here.")
        if profile.key == "linux_best_effort":
            return CommandSupport(command, profile, "best_effort", "This Linux distro is outside the official support matrix, so analysis runs in best-effort mode.")
        return CommandSupport(command, profile, "official", "")

    if command in remote_commands:
        if profile.key == "windows_remote":
            return CommandSupport(command, profile, "official", "")
        if profile.key in ("ubuntu_standalone", "pi_standalone", "linux_best_effort"):
            return CommandSupport(command, profile, "best_effort", "Remote-controller commands remain available on Linux, but the official Linux modes are standalone.")
        return CommandSupport(command, profile, "experimental", "Remote-controller commands are not part of the official macOS/experimental workflow.")

    if command in local_validation_commands:
        if profile.key in ("ubuntu_standalone", "pi_standalone"):
            return CommandSupport(command, profile, "official", "")
        if profile.key == "linux_best_effort":
            return CommandSupport(command, profile, "best_effort", "Standalone validation runs outside the official support matrix on this Linux distro.")
        if profile.key == "windows_remote":
            experimental = PRODUCT_PROFILES["windows_experimental_local"]
            return CommandSupport(command, experimental, "experimental", "Standalone local validation is experimental on Windows because native capture is not an official Windows mode.")
        return CommandSupport(command, profile, "experimental", "Standalone local validation is not part of an official product mode on this platform.")

    if command in local_capture_commands or (command == "all" and not has_input_pcap):
        if profile.key in ("ubuntu_standalone", "pi_standalone"):
            return CommandSupport(command, profile, "official", "")
        if profile.key == "linux_best_effort":
            return CommandSupport(command, profile, "best_effort", "Local capture is available, but this Linux distro is outside the official support matrix.")
        if profile.key == "windows_remote":
            experimental = PRODUCT_PROFILES["windows_experimental_local"]
            return CommandSupport(command, experimental, "experimental", "Local capture on Windows is available only through the experimental local-capture profile.")
        return CommandSupport(command, profile, "experimental", "Local capture is not an official product mode on this platform.")

    if command in local_wifi_commands:
        if profile.key in ("ubuntu_standalone", "pi_standalone"):
            return CommandSupport(command, profile, "official", "")
        if profile.key == "linux_best_effort":
            return CommandSupport(command, profile, "best_effort", "Local monitor-mode and Wi-Fi lab commands are available, but this distro is outside the official support matrix.")
        if profile.key == "windows_remote":
            experimental = PRODUCT_PROFILES["windows_experimental_local"]
            return CommandSupport(command, experimental, "experimental", "Native Windows monitor-mode and Wi-Fi lab commands remain experimental.")
        return CommandSupport(command, profile, "experimental", "Monitor-mode and Wi-Fi lab commands are not part of an official product mode on this platform.")

    return CommandSupport(command, profile, "official", "")


def workflow_support_matrix(config: Optional[Dict[str, object]] = None) -> List[WorkflowSupport]:
    profile = resolve_product_profile(config)

    has_dumpcap = _tool_available("dumpcap")
    has_tcpdump = _tool_available("tcpdump")
    has_tshark = _tool_available("tshark")
    has_ssh = _tool_available("ssh")
    has_scp = _tool_available("scp")
    has_airmon = _tool_available("airmon-ng")
    has_airodump = _tool_available("airodump-ng")
    has_aircrack = _tool_available("aircrack-ng")
    has_airdecap = _tool_available("airdecap-ng")
    has_wlanhelper = _tool_available("WlanHelper")

    supports_local_capture = has_dumpcap or has_tcpdump
    supports_remote_control = has_ssh and has_scp
    supports_monitor_toolchain = has_airmon or has_airodump or has_wlanhelper or has_tcpdump
    supports_wifi_toolchain = has_aircrack and has_airdecap

    rows: List[WorkflowSupport] = []

    analysis_tier = "supported" if profile.official else "supported_with_limits"
    analysis_detail = (
        "Importing a pcap and running extract/detect/analyze is a first-class workflow here."
        if profile.official
        else "Analysis remains available here, but this platform sits outside the narrow official support matrix."
    )
    rows.append(
        WorkflowSupport(
            area="pcap import + analysis",
            tier=analysis_tier,
            summary="Import an existing pcap and run the analysis pipeline.",
            detail=analysis_detail,
        )
    )

    if profile.key in ("ubuntu_standalone", "pi_standalone"):
        capture_tier = "supported" if supports_local_capture else "unsupported"
        capture_detail = (
            "The standalone Linux workflow is fully supported when dumpcap or tcpdump is installed."
            if supports_local_capture
            else "This official Linux workflow still needs a local capture tool such as dumpcap or tcpdump."
        )
    elif profile.key == "linux_best_effort":
        capture_tier = "supported_with_limits" if supports_local_capture else "unsupported"
        capture_detail = (
            "Local capture is available, but this Linux distro is outside the official support matrix."
            if supports_local_capture
            else "This best-effort Linux workflow still needs a local capture tool such as dumpcap or tcpdump."
        )
    elif profile.key == "windows_remote":
        capture_tier = "supported_with_limits" if supports_local_capture else "unsupported"
        capture_detail = (
            "Windows can still import or do basic local capture, but local capture is no longer the primary supported workflow."
            if supports_local_capture
            else "Windows local capture is not the main workflow and the required capture tools are missing."
        )
    else:
        capture_tier = "supported_with_limits" if supports_local_capture else "unsupported"
        capture_detail = (
            "Local capture is present, but this platform remains experimental."
            if supports_local_capture
            else "Local capture tools are missing on this experimental platform."
        )
    rows.append(
        WorkflowSupport(
            area="local packet capture",
            tier=capture_tier,
            summary="Capture a pcap on the current machine.",
            detail=capture_detail,
        )
    )

    if profile.key in ("ubuntu_standalone", "pi_standalone"):
        monitor_tier = "supported" if supports_monitor_toolchain else "unsupported"
        monitor_detail = (
            "Monitor-mode and Wi-Fi lab flows are part of the official Linux story when the toolchain and adapter are present."
            if supports_monitor_toolchain
            else "The official Linux Wi-Fi workflow still needs monitor-mode tooling and compatible hardware."
        )
    elif profile.key == "linux_best_effort":
        monitor_tier = "supported_with_limits" if supports_monitor_toolchain else "unsupported"
        monitor_detail = (
            "Monitor-mode can be attempted here, but this Linux distro is outside the official support matrix."
            if supports_monitor_toolchain
            else "This best-effort Linux workflow still needs monitor-mode tooling and compatible hardware."
        )
    elif profile.key == "windows_remote":
        monitor_tier = "supported_with_limits" if supports_monitor_toolchain else "unsupported"
        monitor_detail = (
            "Native Windows monitor-mode remains experimental and adapter-dependent even when helper tools are installed."
            if supports_monitor_toolchain
            else "Native Windows monitor-mode is not the supported path and the local helper tools are missing."
        )
    else:
        monitor_tier = "supported_with_limits" if supports_monitor_toolchain else "unsupported"
        monitor_detail = (
            "Monitor-mode may be attempted here, but this platform remains experimental."
            if supports_monitor_toolchain
            else "Monitor-mode tooling is missing on this experimental platform."
        )
    rows.append(
        WorkflowSupport(
            area="monitor mode + Wi-Fi lab capture",
            tier=monitor_tier,
            summary="Run monitor-mode capture, handshake collection, and other Wi-Fi lab steps.",
            detail=monitor_detail,
        )
    )

    if profile.key == "windows_remote":
        remote_tier = "supported" if supports_remote_control else "unsupported"
        remote_detail = (
            "Remote capture is the primary Windows workflow when SSH and SCP are available."
            if supports_remote_control
            else "The Windows remote workflow needs both ssh and scp installed locally."
        )
    elif profile.key in ("ubuntu_standalone", "pi_standalone", "linux_best_effort"):
        remote_tier = "supported_with_limits" if supports_remote_control else "unsupported"
        remote_detail = (
            "Linux can act as a capture appliance too, but that is a secondary workflow here."
            if supports_remote_control
            else "This machine can only act as a remote capture appliance after ssh/scp tooling is available."
        )
    else:
        remote_tier = "unsupported"
        remote_detail = "Remote appliance control is not part of the official workflow on this platform."
    rows.append(
        WorkflowSupport(
            area="remote capture control",
            tier=remote_tier,
            summary="Control a remote capture appliance and pull capture artifacts back.",
            detail=remote_detail,
        )
    )

    if supports_wifi_toolchain and profile.key in ("ubuntu_standalone", "pi_standalone", "windows_remote", "linux_best_effort"):
        crack_tier = "supported_with_limits"
        crack_detail = "Cracking and Wi-Fi decryption are available, but they still depend on handshake quality, passwords/wordlists, and hardware conditions."
    elif supports_wifi_toolchain:
        crack_tier = "supported_with_limits"
        crack_detail = "Cracking tools are installed, but this platform remains outside the official Wi-Fi workflow."
    else:
        crack_tier = "unsupported"
        crack_detail = "Cracking and Wi-Fi decryption need both aircrack-ng and airdecap-ng installed."
    rows.append(
        WorkflowSupport(
            area="WPA cracking + Wi-Fi decrypt",
            tier=crack_tier,
            summary="Turn a usable handshake capture into decrypted packet data.",
            detail=crack_detail,
        )
    )

    decode_detail = "Decoding and candidate ranking are still heuristic because the pipeline may be dealing with unknown or encrypted payloads."
    rows.append(
        WorkflowSupport(
            area="payload decoding",
            tier="heuristic",
            summary="Infer promising payload candidates from extracted traffic.",
            detail=decode_detail,
        )
    )
    rows.append(
        WorkflowSupport(
            area="replay + reconstruction",
            tier="heuristic",
            summary="Attempt to reconstruct or replay candidate output from the analysis results.",
            detail="Replay and reconstruction remain heuristic even on the supported workflows and may still fail cleanly when the capture does not contain enough signal.",
        )
    )

    return sorted(rows, key=lambda row: (_tier_sort_key(row.tier), row.area))


def _host_hardware_qualification(profile: ProductProfile, config: Optional[Dict[str, object]] = None) -> HardwareQualification:
    config = config or {}
    arch = _machine_architecture()
    remote_host = str(config.get("remote_host") or "").strip()

    if profile.key == "windows_remote":
        return HardwareQualification(
            area="host",
            label=f"Windows controller host ({arch})",
            status="supported",
            summary="Qualified controller/analyzer host for the official Windows workflow.",
            detail="Keep packet capture on an Ubuntu or Raspberry Pi OS capture node; this Windows machine is the supported control and analysis side.",
            monitor_mode="handled by Linux capture node",
            injection="handled by Linux capture node",
            channels="depends on remote node",
        )

    if profile.key == "ubuntu_standalone":
        return HardwareQualification(
            area="host",
            label=f"Ubuntu standalone host ({arch})",
            status="supported",
            summary="Qualified full local host for the supported Ubuntu standalone workflow.",
            detail="Ubuntu is the primary standalone Linux target and can also double as a Windows capture node when needed.",
            monitor_mode="supported with a qualified adapter",
            injection="qualified adapters only",
            channels="adapter dependent",
        )

    if profile.key == "pi_standalone":
        model = _linux_machine_model() or "Raspberry Pi"
        return HardwareQualification(
            area="host",
            label=f"{model} host",
            status="supported",
            summary="Qualified compact/appliance host for the supported Raspberry Pi OS workflow.",
            detail="Raspberry Pi OS is an official target, but the full Wi-Fi lab path still expects a qualified USB capture adapter rather than the typical onboard Broadcom radio.",
            monitor_mode="supported with a qualified USB adapter",
            injection="qualified USB adapters only",
            channels="adapter dependent",
        )

    if profile.key == "linux_best_effort":
        distro = linux_distribution_label() or f"Linux ({arch})"
        return HardwareQualification(
            area="host",
            label=distro,
            status="supported_with_limits",
            summary="This Linux host can often run the pipeline, but the distro is outside the official matrix.",
            detail="Ubuntu and Raspberry Pi OS are the only Linux targets we qualify end to end. Other distros stay best effort even with the right adapter.",
            monitor_mode="toolchain dependent",
            injection="adapter dependent",
            channels="adapter dependent",
        )

    return HardwareQualification(
        area="host",
        label=f"macOS host ({arch})" if IS_MACOS else f"Unsupported host ({arch})",
        status="unsupported",
        summary="This host platform is outside the supported hardware program.",
        detail="Stay on Ubuntu standalone, Raspberry Pi OS standalone, or Windows paired with a Linux capture node for the narrow supported path.",
        monitor_mode="experimental",
        injection="experimental",
        channels="adapter dependent",
    )


def _windows_hardware_rows(config: Optional[Dict[str, object]] = None) -> List[HardwareQualification]:
    config = config or {}
    remote_host = str(config.get("remote_host") or "").strip()
    remote_profile = str(config.get("remote_install_profile") or "appliance")
    remote_status = "supported" if remote_host else "supported_with_limits"
    remote_detail = (
        f"Configured capture node: {remote_host}. Keep using the appliance profile for the most predictable Windows experience."
        if remote_host
        else "Run .\\setup_remote.ps1 or bootstrap-remote against an Ubuntu or Raspberry Pi OS node; that is the supported Windows capture path."
    )
    rows = [
        HardwareQualification(
            area="capture_node",
            label="Ubuntu or Raspberry Pi OS capture node",
            status=remote_status,
            summary="The supported capture-node targets are Ubuntu standalone, Raspberry Pi OS standalone, or an appliance-profile remote node.",
            detail=remote_detail,
            monitor_mode="qualified on the Linux node with a supported adapter",
            injection="qualified Linux USB adapters only",
            channels="depends on node radio",
        ),
        HardwareQualification(
            area="local_radio",
            label="Native Windows 802.11 adapter",
            status="unsupported",
            summary="No native Windows adapter family is part of the official hardware program.",
            detail="Even when NPcap and WlanHelper see the adapter, monitor and injection behavior stay driver dependent. Treat local Windows Wi-Fi capture as experimental only.",
            monitor_mode="experimental",
            injection="experimental",
            channels="adapter dependent",
        ),
    ]
    if remote_profile == "appliance":
        rows[0] = HardwareQualification(
            area=rows[0].area,
            label=rows[0].label,
            status=rows[0].status,
            summary=rows[0].summary,
            detail=rows[0].detail,
            monitor_mode=rows[0].monitor_mode,
            injection=rows[0].injection,
            channels=f"{rows[0].channels}; appliance profile preferred",
        )
    return rows


def _linux_hardware_rows(config: Optional[Dict[str, object]] = None) -> List[HardwareQualification]:
    config = config or {}
    profile = resolve_product_profile(config)
    requested = str(config.get("interface") or "").strip()
    seen: set[str] = set()
    interface_rows: List[HardwareQualification] = []

    candidates = list_interfaces()
    if requested and not any(name == requested for _number, name, _description in candidates):
        candidates = [("0", requested, "configured capture interface")] + candidates

    for _number, name, description in candidates:
        if name in seen:
            continue
        seen.add(name)
        driver = _linux_interface_driver(name)
        fingerprint = _linux_interface_fingerprint(name, description)
        entry = _match_hardware_catalog(fingerprint, profile.key)

        if entry:
            interface_rows.append(
                HardwareQualification(
                    area="capture_adapter",
                    label=f"{name} ({entry.family})",
                    status=entry.status,
                    summary=f"Driver `{driver or 'unknown'}` maps to the {entry.family} capture family.",
                    detail=entry.detail,
                    monitor_mode=entry.monitor_mode,
                    injection=entry.injection,
                    channels=entry.channels,
                )
            )
            continue

        if driver:
            interface_rows.append(
                HardwareQualification(
                    area="capture_adapter",
                    label=f"{name} ({driver})",
                    status="unsupported",
                    summary="This adapter family is not in the narrow qualified hardware list yet.",
                    detail="It may still work for pcap-first or best-effort capture, but the full supported Wi-Fi lab path is only qualified for the documented Linux adapter families.",
                    monitor_mode="unknown",
                    injection="unknown",
                    channels="unknown",
                )
            )
        else:
            interface_rows.append(
                HardwareQualification(
                    area="capture_adapter",
                    label=name,
                    status="supported_with_limits",
                    summary="Wireless interface detected, but the driver family could not be fingerprinted from sysfs.",
                    detail="Re-run on Linux with a configured interface if you want adapter qualification, or use the pcap-first flow until the adapter family is known.",
                    monitor_mode="unknown",
                    injection="unknown",
                    channels="unknown",
                )
            )

    if interface_rows:
        return interface_rows

    return [
        HardwareQualification(
            area="capture_adapter",
            label="No wireless interface detected",
            status="unsupported" if profile.key in ("ubuntu_standalone", "pi_standalone") else "supported_with_limits",
            summary="The host is present, but no local wireless capture adapter was detected.",
            detail="Standalone Linux needs a detectable wireless adapter for live capture. You can still use the pcap-first flow without one.",
            monitor_mode="missing",
            injection="missing",
            channels="missing",
        )
    ]


def hardware_qualification_report(config: Optional[Dict[str, object]] = None) -> List[HardwareQualification]:
    profile = resolve_product_profile(config)
    rows = [_host_hardware_qualification(profile, config)]
    if profile.key == "windows_remote":
        rows.extend(_windows_hardware_rows(config))
    elif IS_LINUX:
        rows.extend(_linux_hardware_rows(config))
    else:
        rows.append(
            HardwareQualification(
                area="capture_adapter",
                label="Local wireless adapter",
                status="unsupported",
                summary="This platform is outside the supported local capture hardware program.",
                detail="Use Ubuntu or Raspberry Pi OS for the capture side, or keep this machine in controller/analyzer mode only.",
                monitor_mode="experimental",
                injection="experimental",
                channels="adapter dependent",
            )
        )
    return sorted(rows, key=lambda row: (_tier_sort_key(row.status), row.area, row.label))


def print_hardware_qualification(config: Optional[Dict[str, object]] = None) -> List[HardwareQualification]:
    rows = hardware_qualification_report(config)
    print(f"\n  {BOLD}Hardware Qualification{RESET}")
    for row in rows:
        if row.status == "supported":
            status_text = f"{GREEN}{_tier_label(row.status)}{RESET}"
        elif row.status == "supported_with_limits":
            status_text = f"{YELLOW}{_tier_label(row.status)}{RESET}"
        else:
            status_text = f"{RED}{_tier_label(row.status)}{RESET}"
        print(f"    {row.label:<34} {status_text}")
        print(f"      {row.summary}")
        print(f"      {row.detail}")
        print(
            "      "
            f"monitor={row.monitor_mode}; injection={row.injection}; channels={row.channels}"
        )
    return rows


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    # Linux / macOS: check for root
    return os.geteuid() == 0


def relaunch_as_admin(argv: Optional[List[str]] = None) -> None:
    if not IS_WINDOWS:
        raise RuntimeError("UAC elevation helper is Windows-only; use sudo on Linux/macOS.")
    import ctypes
    argv = list(sys.argv[1:] if argv is None else argv)
    script = os.path.abspath(sys.argv[0])
    args = " ".join([f'"{script}"'] + [f'"{item}"' for item in argv])
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1)
    if result <= 32:
        raise RuntimeError(f"UAC elevation failed with code {result}")


def check_environment(config: Optional[Dict[str, object]] = None) -> bool:
    section("Environment Check")
    profile = resolve_product_profile(config)

    if IS_WINDOWS:
        platform_tools = WINDOWS_TOOLS
    elif IS_MACOS:
        platform_tools = MACOS_TOOLS
    else:
        platform_tools = LINUX_TOOLS
    all_required = True

    ok(f"Python runtime: {sys.executable} ({sys.version.split()[0]})")
    info(f"Active product profile: {profile.label}")

    for name, purpose, required in platform_tools:
        path = _tool_path(name)
        status = f"{CYAN}*{RESET}" if path else f"{DIM}-{RESET}"
        requirement = "required" if required else "optional"
        location = path or "not found on PATH"
        print(f"  {status} {name:<16} {purpose} {DIM}({requirement}){RESET}")
        print(f"      {location}")
        if required and not path:
            all_required = False

    # Python packages
    for pkg in ("scapy", "numpy"):
        try:
            __import__(pkg)
            ok(f"Python package available: {pkg}")
        except ImportError:
            warn(f"Python package missing: {pkg}")
            if pkg == "scapy":
                all_required = False

    if not is_admin():
        if IS_WINDOWS:
            warn("Administrator rights are recommended for capture and interface discovery.")
        else:
            warn("Root (sudo) is required for monitor mode and raw socket capture on Linux/macOS.")

    if IS_WINDOWS:
        info("Official Windows mode: controller/analyzer on Windows 10/11 with Ubuntu or Raspberry Pi OS handling remote capture.")
        info("Ubuntu standalone and Raspberry Pi OS standalone are the Linux-first supported product modes.")
        warn("Native Windows monitor-mode and Wi-Fi lab capture remain experimental and adapter-dependent.")
        warn("Unsupported as a guaranteed product path: adapter-independent Windows 802.11 monitor/injection parity with Linux.")
    elif IS_LINUX:
        distro_label = linux_distribution_label()
        if distro_label:
            info(f"Detected Linux target: {distro_label}")
        info("Official Linux modes: Ubuntu standalone and Raspberry Pi OS standalone.")
        info("The same Linux toolchain can also act as the remote capture side for Windows controller runs.")
        warn("Other Linux distributions may work, but Ubuntu and Raspberry Pi OS are the only officially supported Linux targets.")
        warn("Raw capture still requires root or capture capabilities even on the supported Linux path.")
    elif IS_MACOS:
        info("macOS support remains experimental; the official product modes are Ubuntu standalone, Raspberry Pi OS standalone, or Windows with Linux remote capture.")
        warn("macOS is not an officially supported standalone or capture-appliance target.")

    print(f"\n  {BOLD}Workflow Tiers{RESET}")
    for row in workflow_support_matrix(config):
        if row.tier == "supported":
            tier_text = f"{GREEN}{_tier_label(row.tier)}{RESET}"
        elif row.tier == "supported_with_limits":
            tier_text = f"{YELLOW}{_tier_label(row.tier)}{RESET}"
        elif row.tier == "heuristic":
            tier_text = f"{YELLOW}{_tier_label(row.tier)}{RESET}"
        else:
            tier_text = f"{RED}{_tier_label(row.tier)}{RESET}"
        print(f"    {row.area:<30} {tier_text}")
        print(f"      {row.detail}")

    print_hardware_qualification(config)

    info("Long-term limit: replay, payload decoding, and reconstruction remain heuristic and are not guaranteed.")

    return all_required


def _parse_dumpcap_interfaces(output: str) -> List[Tuple[str, str, str]]:
    interfaces: List[Tuple[str, str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or "." not in line:
            continue
        number, rest = line.split(".", 1)
        number = number.strip()
        rest = rest.strip()
        if "(" in rest and rest.endswith(")"):
            name = rest[: rest.index("(")].strip()
            description = rest[rest.index("(") + 1 : -1].strip()
        else:
            name = rest
            description = ""
        interfaces.append((number, name, description))
    return interfaces


def _list_linux_interfaces() -> List[Tuple[str, str, str]]:
    """List wireless interfaces on Linux using iw or iwconfig."""
    interfaces: List[Tuple[str, str, str]] = []
    iw = shutil.which("iw")
    if iw:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=5, check=False
        )
        current_iface = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                current_iface = line.split()[1]
                interfaces.append((str(len(interfaces) + 1), current_iface, "wireless (iw)"))
        if interfaces:
            return interfaces

    # Fallback: /sys/class/net
    net_path = "/sys/class/net"
    if os.path.isdir(net_path):
        for index, name in enumerate(sorted(os.listdir(net_path)), start=1):
            if name.startswith(("wlan", "wlp", "ath", "mon")):
                interfaces.append((str(index), name, "wireless"))
    return interfaces


def _list_macos_interfaces() -> List[Tuple[str, str, str]]:
    """List network interfaces on macOS using networksetup."""
    interfaces: List[Tuple[str, str, str]] = []
    try:
        result = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        current_port = ""
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Hardware Port:"):
                current_port = line.split(":", 1)[1].strip()
            elif line.startswith("Device:") and current_port:
                iface = line.split(":", 1)[1].strip()
                if iface:
                    interfaces.append((str(len(interfaces) + 1), iface, current_port))
                current_port = ""
    except (OSError, subprocess.TimeoutExpired):
        pass

    if not interfaces:
        # Fallback: list all interfaces from ifconfig
        try:
            result = subprocess.run(
                ["ifconfig", "-l"], capture_output=True, text=True, timeout=5, check=False,
            )
            for index, name in enumerate(result.stdout.split(), start=1):
                interfaces.append((str(index), name, "network interface"))
        except (OSError, subprocess.TimeoutExpired):
            pass

    return interfaces


def list_interfaces() -> List[Tuple[str, str, str]]:
    if IS_MACOS:
        return _list_macos_interfaces()
    if IS_LINUX:
        return _list_linux_interfaces()
    if not IS_WINDOWS:
        return []

    dumpcap = shutil.which("dumpcap")
    if dumpcap:
        try:
            result = subprocess.run(
                [dumpcap, "-D"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except OSError:
            result = None
        if result and result.stdout.strip():
            parsed = _parse_dumpcap_interfaces(result.stdout)
            if parsed:
                return parsed

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetAdapter | Select-Object Name,InterfaceDescription,InterfaceGuid "
                "| ConvertTo-Csv -NoTypeInformation",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except OSError:
        return []

    interfaces: List[Tuple[str, str, str]] = []
    for index, line in enumerate(result.stdout.splitlines()[1:], start=1):
        parts = [part.strip().strip('"') for part in line.split('","')]
        if len(parts) < 3:
            continue
        name = f"\\\\Device\\\\NPF_{{{parts[2].strip('{}')}}}"
        description = f"{parts[0]} - {parts[1]}"
        interfaces.append((str(index), name, description))
    return interfaces


def pick_interface(current: str) -> str:
    interfaces = list_interfaces()
    if not interfaces:
        warn("Unable to enumerate interfaces automatically.")
        if IS_WINDOWS:
            print(f"  {BOLD}Tip:{RESET} install Wireshark/NPcap and re-run in an Administrator shell.")
        elif IS_MACOS:
            print(f"  {BOLD}Tip:{RESET} run as root (sudo) and ensure Xcode CLI tools are installed.")
        else:
            print(f"  {BOLD}Tip:{RESET} install iw ('sudo apt install iw') and re-run as root.")
        return ask("Capture interface", current or "")

    section("Available Interfaces")
    for number, name, description in interfaces:
        label = f"  {number}. {name}"
        if description:
            label += f" {DIM}({description}){RESET}"
        print(label)

    selected = ask("Enter interface number or full name", current or interfaces[0][1])
    for number, name, _description in interfaces:
        if selected == number:
            ok(f"Selected {name}")
            return name
    return selected


def maybe_elevate_for_capture(interactive: bool = True) -> bool:
    if IS_LINUX or IS_MACOS:
        if not is_admin():
            warn("Monitor mode and raw capture require root on Linux/macOS. Re-run with sudo.")
        return False   # Don't block — let the underlying tool produce the real error
    if not IS_WINDOWS:
        return False
    if is_admin():
        return False
    warn("Capture usually needs Administrator rights on Windows.")
    if not interactive:
        info("Continuing without elevation because this run is non-interactive.")
        return False
    if confirm("Relaunch as Administrator now?", default=True):
        relaunch_as_admin()
        return True
    info("Continuing without elevation. Capture may fail.")
    return False
