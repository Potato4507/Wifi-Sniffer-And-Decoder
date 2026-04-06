from __future__ import annotations

import copy
import json
import os
import sys
from typing import Dict, Optional

from .environment import IS_MACOS, IS_WINDOWS, default_product_mode, pick_interface, resolve_product_profile
from .ui import ask, ask_int, confirm, ok, section, warn

DEFAULT_CONFIG = {
    "product_mode": default_product_mode(),
    # ── environment ───────────────────────────────────────────────────────────
    "environment_model": (
        "native_windows" if sys.platform.startswith("win")
        else "macos" if sys.platform == "darwin"
        else "linux"
    ),
    # ── capture ───────────────────────────────────────────────────────────────
    "interface": "",
    "target_macs": [],
    "capture_duration": 60,
    "output_dir": "./pipeline_output",
    # ── Wi-Fi / WPA ───────────────────────────────────────────────────────────
    "ap_essid": "",
    "ap_bssid": "",
    "ap_channel": 6,
    "wpa_password": "",
    "wpa_password_env": "WIFI_PIPELINE_WPA_PASSWORD",
    # ── wi-fi lab pipeline (monitor mode + cracking) ─────────────────────────────
    "wordlist_path": "/usr/share/wordlists/rockyou.txt",
    "handshake_timeout": 120,
    "crack_timeout": 600,
    "deauth_count": 10,
    "hashcat_rules": "",
    "monitor_method": "airodump",   # airodump | besside | tcpdump
    # ── remote capture (optional) ──────────────────────────────────────────
    "remote_host": "",
    "remote_path": "",
    "remote_port": 22,
    "remote_identity": "",
    "remote_interface": "",
    "remote_install_mode": "auto",
    "remote_install_profile": "appliance",
    "remote_health_port": 8741,
    "remote_dest_dir": "./pipeline_output/remote_imports",
    "remote_poll_interval": 8,
    # ── extraction ────────────────────────────────────────────────────────────
    "video_port": 5004,
    "protocol": "udp",
    "custom_header_size": 0,
    "custom_magic_hex": "",
    # ── analysis / corpus ─────────────────────────────────────────────────────
    "preferred_stream_id": "",
    "min_candidate_bytes": 4096,
    "replay_format_hint": "raw",
    "corpus_review_threshold": 0.62,
    "corpus_auto_reuse_threshold": 0.88,
    # ── playback ──────────────────────────────────────────────────────────────
    "video_codec": "mpegts",
    "live_output_port": 5005,
    "playback_mode": "both",
    "jitter_buffer_packets": 24,
}


def _copy_default_config() -> Dict[str, object]:
    return copy.deepcopy(DEFAULT_CONFIG)


def _running_environment_model() -> str:
    if IS_WINDOWS:
        return "native_windows"
    if IS_MACOS:
        return "macos"
    return "linux"


def _emit_status(message: str, *, quiet: bool = False) -> None:
    if not quiet:
        ok(message)


def _emit_warning(message: str, *, quiet: bool = False) -> None:
    if not quiet:
        warn(message)


def normalize_config(config: Dict[str, object], *, quiet: bool = False) -> Dict[str, object]:
    normalized = _copy_default_config()
    normalized.update(dict(config))

    # Correct environment_model for the actual running platform so that
    # platform-specific tool lists and capture paths are always consistent.
    expected_model = _running_environment_model()
    current_model = normalized.get("environment_model")
    if expected_model == "native_windows" and current_model != "native_windows":
        _emit_warning("Overriding environment_model with native_windows on this platform.", quiet=quiet)
        normalized["environment_model"] = "native_windows"
    elif expected_model == "macos" and current_model not in ("macos", "linux"):
        _emit_warning("Overriding environment_model with macos on this platform.", quiet=quiet)
        normalized["environment_model"] = "macos"
    elif expected_model == "linux" and current_model == "native_windows":
        _emit_warning("Overriding environment_model with linux on this platform.", quiet=quiet)
        normalized["environment_model"] = "linux"

    requested_mode = str(normalized.get("product_mode") or "").strip()
    resolved_profile = resolve_product_profile(normalized)
    if requested_mode and requested_mode != resolved_profile.key:
        _emit_warning(f"Overriding product_mode with {resolved_profile.key} on this platform.", quiet=quiet)
    normalized["product_mode"] = resolved_profile.key

    if not normalized.get("replay_format_hint"):
        normalized["replay_format_hint"] = normalized.get("video_codec") or "raw"

    return normalized


def load_config(
    path: Optional[str] = None,
    *,
    quiet: bool = False,
    ignore_errors: bool = False,
) -> Dict[str, object]:
    config = _copy_default_config()
    selected_path = path or "lab.json"
    if selected_path and os.path.exists(selected_path):
        try:
            with open(selected_path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if not isinstance(loaded, dict):
                raise ValueError(f"Config file must contain a JSON object: {selected_path}")
            config.update(loaded)
            _emit_status(f"Config loaded from {selected_path}", quiet=quiet)
        except (OSError, json.JSONDecodeError, ValueError):
            if not ignore_errors:
                raise

    return normalize_config(config, quiet=quiet)


def save_config(config: Dict[str, object], path: Optional[str] = "lab.json", *, quiet: bool = False) -> None:
    sanitized = normalize_config(config, quiet=True)
    # Never persist the raw password to disk
    sanitized["wpa_password"] = ""
    selected_path = path or "lab.json"
    with open(selected_path, "w", encoding="utf-8") as handle:
        json.dump(sanitized, handle, indent=2)
    _emit_status(f"Config saved to {selected_path}", quiet=quiet)


def resolve_wpa_password(config: Dict[str, object]) -> str:
    env_name = str(config.get("wpa_password_env") or "").strip()
    if env_name and os.getenv(env_name):
        return os.getenv(env_name, "")
    return str(config.get("wpa_password") or "")


def interactive_config(config: Dict[str, object]) -> Dict[str, object]:
    section("Configuration")
    profile = resolve_product_profile(config)
    ok(f"Active product mode: {profile.label}")
    warn(profile.description)

    # ── interface ────────────────────────────────────────────────────────────
    if confirm("Pick the capture interface from a discovered list?", default=True):
        config["interface"] = pick_interface(str(config.get("interface") or ""))
    else:
        config["interface"] = ask("Capture interface", str(config.get("interface") or ""))

    macs = ask(
        "Target MACs (comma-separated, blank keeps all traffic)",
        ",".join(config.get("target_macs", [])),
    )
    config["target_macs"] = [item.strip() for item in macs.split(",") if item.strip()]

    # ── Wi-Fi / WPA ──────────────────────────────────────────────────────────
    config["ap_essid"] = ask("AP ESSID for Wi-Fi strip / crack", str(config.get("ap_essid") or ""))
    config["ap_bssid"] = ask("AP BSSID (MAC of access point)", str(config.get("ap_bssid") or ""))
    config["ap_channel"] = ask_int("AP channel", int(config.get("ap_channel", 6)))

    # ── wi-fi lab pipeline ───────────────────────────────────────────────────
    section("Monitor Mode / WPA2 Cracking (wi-fi lab pipeline)")
    config["monitor_method"] = ask(
        "Handshake capture method (airodump/besside/tcpdump)",
        str(config.get("monitor_method") or "airodump"),
    ).lower()
    config["handshake_timeout"] = ask_int(
        "Handshake capture timeout in seconds",
        int(config.get("handshake_timeout", 120)),
    )
    config["deauth_count"] = ask_int(
        "Deauth frames to send (0 = passive capture only)",
        int(config.get("deauth_count", 10)),
    )
    config["wordlist_path"] = ask(
        "Wordlist path for aircrack-ng / hashcat",
        str(config.get("wordlist_path") or "/usr/share/wordlists/rockyou.txt"),
    )
    config["crack_timeout"] = ask_int(
        "Crack timeout in seconds",
        int(config.get("crack_timeout", 600)),
    )
    config["hashcat_rules"] = ask(
        "Hashcat rules file path (optional)",
        str(config.get("hashcat_rules") or ""),
    )

    # ── extraction ───────────────────────────────────────────────────────────
    section("Extraction")
    config["video_port"] = ask_int("Target payload port", int(config.get("video_port", 5004)))
    protocol = ask("Transport protocol (udp/tcp)", str(config.get("protocol") or "udp")).lower()
    config["protocol"] = "tcp" if protocol == "tcp" else "udp"
    config["capture_duration"] = ask_int(
        "Capture duration in seconds (0 = manual stop)",
        int(config.get("capture_duration", 60)),
    )
    config["output_dir"] = ask("Output directory", str(config.get("output_dir") or "./pipeline_output"))
    config["custom_header_size"] = ask_int(
        "Bytes to strip after the transport header",
        int(config.get("custom_header_size", 0)),
    )
    config["custom_magic_hex"] = ask(
        "Optional custom magic/header bytes in hex",
        str(config.get("custom_magic_hex") or ""),
    ).replace(" ", "")
    config["preferred_stream_id"] = ask(
        "Preferred stream ID to analyze first (optional)",
        str(config.get("preferred_stream_id") or ""),
    )
    config["min_candidate_bytes"] = ask_int(
        "Minimum bytes for a stream to count as a serious candidate",
        int(config.get("min_candidate_bytes", 4096)),
    )
    config["replay_format_hint"] = ask(
        "Replay format hint (raw/txt/json/xml/jpeg/png/webp/wav/mp3/ogg/flac/aac/mpegts/h264/h265)",
        str(config.get("replay_format_hint") or config.get("video_codec") or "raw"),
    )

    # ── corpus ───────────────────────────────────────────────────────────────
    review_threshold = ask(
        "Corpus similarity score to surface an archived match",
        str(config.get("corpus_review_threshold", 0.62)),
    )
    try:
        config["corpus_review_threshold"] = float(review_threshold)
    except ValueError:
        warn(f"Invalid value {review_threshold!r}; keeping {config.get('corpus_review_threshold', 0.62)}.")

    auto_reuse_threshold = ask(
        "Corpus similarity score to auto-reuse archived candidate material",
        str(config.get("corpus_auto_reuse_threshold", 0.88)),
    )
    try:
        config["corpus_auto_reuse_threshold"] = float(auto_reuse_threshold)
    except ValueError:
        warn(f"Invalid value {auto_reuse_threshold!r}; keeping {config.get('corpus_auto_reuse_threshold', 0.88)}.")

    config["video_codec"] = str(config.get("replay_format_hint") or "raw")
    config["playback_mode"] = ask(
        "Playback mode (file/ffplay/both)",
        str(config.get("playback_mode") or "both"),
    ).lower()
    config["jitter_buffer_packets"] = ask_int(
        "UDP jitter buffer size in packets",
        int(config.get("jitter_buffer_packets", 24)),
    )

    # ── WPA password (session only, never saved) ──────────────────────────────
    section("WPA Password")
    env_name = ask(
        "Environment variable name for WPA password",
        str(config.get("wpa_password_env") or "WIFI_PIPELINE_WPA_PASSWORD"),
    )
    config["wpa_password_env"] = env_name
    config["wpa_password"] = ""

    if os.getenv(env_name):
        ok(f"Using WPA password from environment variable {env_name}.")
    elif confirm("Provide a session-only WPA password now? (will NOT be saved to disk)", default=False):
        config["wpa_password"] = ask("WPA password", secret=True)

    section("Remote Capture (optional)")
    default_remote = profile.key == "windows_remote"
    if confirm("Configure a remote capture source (SSH/SCP)?", default=default_remote):
        config["remote_host"] = ask(
            "Remote host (user@host)",
            str(config.get("remote_host") or ""),
        )
        config["remote_path"] = ask(
            "Remote capture path (file or directory)",
            str(config.get("remote_path") or ""),
        )
        config["remote_port"] = ask_int(
            "Remote SSH port",
            int(config.get("remote_port", 22)),
        )
        config["remote_identity"] = ask(
            "SSH identity file (optional)",
            str(config.get("remote_identity") or ""),
        )
        config["remote_interface"] = ask(
            "Remote capture interface (optional, for start-remote)",
            str(config.get("remote_interface") or "wlan0"),
        )
        config["remote_install_mode"] = ask(
            "Remote install mode (auto/native/bundle)",
            str(config.get("remote_install_mode") or "auto"),
        ).strip().lower() or "auto"
        config["remote_install_profile"] = ask(
            "Remote install profile (standard/appliance)",
            str(config.get("remote_install_profile") or "appliance"),
        ).strip().lower() or "appliance"
        if str(config.get("remote_install_profile") or "") == "appliance":
            config["remote_health_port"] = ask_int(
                "Remote health endpoint port",
                int(config.get("remote_health_port", 8741)),
            )
        config["remote_dest_dir"] = ask(
            "Local import directory",
            str(config.get("remote_dest_dir") or "./pipeline_output/remote_imports"),
        )
        config["remote_poll_interval"] = ask_int(
            "Remote poll interval in seconds",
            int(config.get("remote_poll_interval", 8)),
        )

    if confirm("Save config to lab.json?", default=True):
        save_config(config)
    return config
