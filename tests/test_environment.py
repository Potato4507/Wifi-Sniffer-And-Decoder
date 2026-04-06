from __future__ import annotations

import shutil

from wifi_pipeline import environment
from wifi_pipeline.environment import _parse_dumpcap_interfaces


def test_parse_dumpcap_interfaces_basic() -> None:
    raw = "1. \\Device\\NPF_{ABC} (Ethernet)\n2. \\Device\\NPF_{DEF} (Wi-Fi)\n"
    parsed = _parse_dumpcap_interfaces(raw)
    assert parsed[0][0] == "1"
    assert parsed[0][1].startswith("\\Device\\NPF_")
    assert parsed[1][2] == "Wi-Fi"


def test_parse_dumpcap_interfaces_no_parens() -> None:
    raw = "1. \\Device\\NPF_{ABC}\n"
    parsed = _parse_dumpcap_interfaces(raw)
    assert parsed[0][1] == "\\Device\\NPF_{ABC}"


def test_default_product_mode_detects_ubuntu(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04 LTS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "")

    assert environment.default_product_mode() == "ubuntu_standalone"
    assert environment.resolve_product_profile({}).label == "Ubuntu standalone"


def test_default_product_mode_detects_raspberry_pi(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "raspbian", "PRETTY_NAME": "Raspberry Pi OS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "Raspberry Pi 5")

    assert environment.default_product_mode() == "pi_standalone"
    assert environment.resolve_product_profile({}).label == "Raspberry Pi OS standalone"


def test_command_support_marks_windows_local_capture_experimental(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", True)
    monkeypatch.setattr(environment, "IS_LINUX", False)
    monkeypatch.setattr(environment, "IS_MACOS", False)

    support = environment.command_support("capture", {})

    assert support.status == "experimental"
    assert support.profile.key == "windows_experimental_local"


def test_command_support_marks_linux_wifi_official(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04 LTS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "")

    support = environment.command_support("wifi", {})

    assert support.status == "official"
    assert support.profile.key == "ubuntu_standalone"


def test_command_support_marks_validate_local_official_on_supported_linux(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04 LTS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "")

    support = environment.command_support("validate-local", {})

    assert support.status == "official"
    assert support.profile.key == "ubuntu_standalone"


def test_workflow_support_matrix_for_windows_remote(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", True)
    monkeypatch.setattr(environment, "IS_LINUX", False)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_find_windows_wlanhelper", lambda: r"C:\Npcap\WlanHelper.exe")

    tool_map = {
        "dumpcap": r"C:\Wireshark\dumpcap.exe",
        "tshark": r"C:\Wireshark\tshark.exe",
        "ssh": r"C:\Windows\System32\OpenSSH\ssh.exe",
        "scp": r"C:\Windows\System32\OpenSSH\scp.exe",
        "aircrack-ng": r"C:\aircrack-ng\aircrack-ng.exe",
        "airdecap-ng": r"C:\aircrack-ng\airdecap-ng.exe",
    }
    monkeypatch.setattr(shutil, "which", lambda name: tool_map.get(name))

    rows = {row.area: row for row in environment.workflow_support_matrix({})}

    assert rows["pcap import + analysis"].tier == "supported"
    assert rows["remote capture control"].tier == "supported"
    assert rows["local packet capture"].tier == "supported_with_limits"
    assert rows["monitor mode + Wi-Fi lab capture"].tier == "supported_with_limits"
    assert rows["WPA cracking + Wi-Fi decrypt"].tier == "supported_with_limits"
    assert rows["payload decoding"].tier == "heuristic"
    assert rows["replay + reconstruction"].tier == "heuristic"


def test_workflow_support_matrix_for_ubuntu_standalone(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04 LTS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "")
    monkeypatch.setattr(environment, "_find_windows_wlanhelper", lambda: None)

    tool_map = {
        "tcpdump": "/usr/sbin/tcpdump",
        "tshark": "/usr/bin/tshark",
        "airmon-ng": "/usr/bin/airmon-ng",
        "airodump-ng": "/usr/bin/airodump-ng",
        "aircrack-ng": "/usr/bin/aircrack-ng",
        "airdecap-ng": "/usr/bin/airdecap-ng",
        "ssh": "/usr/bin/ssh",
        "scp": "/usr/bin/scp",
    }
    monkeypatch.setattr(shutil, "which", lambda name: tool_map.get(name))

    rows = {row.area: row for row in environment.workflow_support_matrix({})}

    assert rows["pcap import + analysis"].tier == "supported"
    assert rows["local packet capture"].tier == "supported"
    assert rows["monitor mode + Wi-Fi lab capture"].tier == "supported"
    assert rows["remote capture control"].tier == "supported_with_limits"
    assert rows["WPA cracking + Wi-Fi decrypt"].tier == "supported_with_limits"


def test_hardware_qualification_for_windows_remote(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", True)
    monkeypatch.setattr(environment, "IS_LINUX", False)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment.platform, "machine", lambda: "AMD64")

    rows = {row.area: row for row in environment.hardware_qualification_report({"remote_host": "pi@raspberrypi"})}

    assert rows["host"].status == "supported"
    assert "controller" in rows["host"].summary.lower()
    assert rows["capture_node"].status == "supported"
    assert rows["local_radio"].status == "unsupported"


def test_hardware_qualification_for_ubuntu_with_ath9k_htc(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04 LTS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "")
    monkeypatch.setattr(environment.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(environment, "list_interfaces", lambda: [("1", "wlan0", "wireless adapter")])
    monkeypatch.setattr(environment, "_linux_interface_driver", lambda interface: "ath9k_htc")
    monkeypatch.setattr(
        environment,
        "_linux_interface_fingerprint",
        lambda interface, description="": "wlan0 ath9k_htc qca9271",
    )

    rows = environment.hardware_qualification_report({"interface": "wlan0"})
    by_area = {row.area: row for row in rows}

    assert by_area["host"].status == "supported"
    adapter_rows = [row for row in rows if row.area == "capture_adapter"]
    assert len(adapter_rows) == 1
    assert adapter_rows[0].status == "supported"
    assert "Atheros AR9271" in adapter_rows[0].label


def test_hardware_qualification_for_pi_with_brcmfmac(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "raspbian", "PRETTY_NAME": "Raspberry Pi OS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "Raspberry Pi 5")
    monkeypatch.setattr(environment.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(environment, "list_interfaces", lambda: [("1", "wlan0", "onboard wireless")])
    monkeypatch.setattr(environment, "_linux_interface_driver", lambda interface: "brcmfmac")
    monkeypatch.setattr(
        environment,
        "_linux_interface_fingerprint",
        lambda interface, description="": "wlan0 brcmfmac broadcom",
    )

    rows = environment.hardware_qualification_report({"interface": "wlan0"})
    adapter_rows = [row for row in rows if row.area == "capture_adapter"]

    assert rows[0].status == "supported"
    assert adapter_rows[0].status == "unsupported"
    assert "Broadcom brcmfmac" in adapter_rows[0].label
