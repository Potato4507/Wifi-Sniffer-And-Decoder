from __future__ import annotations

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
