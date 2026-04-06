from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .ui import BOLD, CYAN, DIM, RESET, ask, confirm, err, info, ok, section, warn

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

    analysis_commands = {"config", "deps", "extract", "detect", "analyze", "play", "corpus", "web", "menu"}
    remote_commands = {"remote", "pair-remote", "bootstrap-remote", "start-remote", "remote-service", "validate-remote", "setup-remote"}
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


def check_environment() -> bool:
    section("Environment Check")
    profile = resolve_product_profile()

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
        if IS_WINDOWS and name.lower().startswith("wlanhelper"):
            path = _find_windows_wlanhelper()
        else:
            path = shutil.which(name)
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
