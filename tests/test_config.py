from __future__ import annotations

import json
from types import SimpleNamespace

from wifi_pipeline.config import load_config, normalize_config, resolve_wpa_password, save_config


def test_resolve_wpa_password_env(monkeypatch) -> None:
    monkeypatch.setenv("WIFI_PIPELINE_WPA_PASSWORD", "secret")
    config = {"wpa_password_env": "WIFI_PIPELINE_WPA_PASSWORD", "wpa_password": ""}
    assert resolve_wpa_password(config) == "secret"


def test_resolve_wpa_password_fallback() -> None:
    config = {"wpa_password_env": "", "wpa_password": "local"}
    assert resolve_wpa_password(config) == "local"


def test_resolve_wpa_password_empty() -> None:
    config = {"wpa_password_env": "MISSING_ENV", "wpa_password": ""}
    assert resolve_wpa_password(config) == ""


def test_load_config_backfills_defaults(tmp_path) -> None:
    config_path = tmp_path / "lab.json"
    config_path.write_text(
        json.dumps({"video_codec": "jpeg", "replay_format_hint": "", "remote_host": "pi@host"}),
        encoding="utf-8",
    )

    loaded = load_config(str(config_path))

    assert loaded["replay_format_hint"] == "jpeg"
    assert loaded["remote_host"] == "pi@host"
    assert loaded["remote_port"] == 22
    assert loaded["remote_install_mode"] == "auto"
    assert loaded["remote_install_profile"] == "appliance"
    assert loaded["remote_health_port"] == 8741
    assert loaded["monitor_method"] == "airodump"
    assert "product_mode" in loaded


def test_load_config_normalizes_product_mode(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "lab.json"
    config_path.write_text(json.dumps({"product_mode": "unsupported_mode"}), encoding="utf-8")
    monkeypatch.setattr("wifi_pipeline.config.resolve_product_profile", lambda config: SimpleNamespace(key="windows_remote"))

    loaded = load_config(str(config_path))

    assert loaded["product_mode"] == "windows_remote"


def test_normalize_config_quiet_still_normalizes_product_mode(monkeypatch) -> None:
    monkeypatch.setattr("wifi_pipeline.config.resolve_product_profile", lambda config: SimpleNamespace(key="windows_remote"))

    normalized = normalize_config({"product_mode": "unsupported_mode"}, quiet=True)

    assert normalized["product_mode"] == "windows_remote"


def test_load_config_ignore_errors_returns_normalized_defaults(tmp_path) -> None:
    config_path = tmp_path / "lab.json"
    config_path.write_text("{not valid json", encoding="utf-8")

    loaded = load_config(str(config_path), quiet=True, ignore_errors=True)

    assert loaded["wpa_password_env"] == "WIFI_PIPELINE_WPA_PASSWORD"
    assert "product_mode" in loaded


def test_save_config_strips_wpa_password(tmp_path) -> None:
    config_path = tmp_path / "lab.json"
    save_config({"wpa_password": "secret", "output_dir": "./pipeline_output"}, str(config_path), quiet=True)

    saved = json.loads(config_path.read_text(encoding="utf-8"))

    assert saved["wpa_password"] == ""
