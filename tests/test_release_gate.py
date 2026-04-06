from __future__ import annotations

import json
from pathlib import Path

from wifi_pipeline.release_gate import evaluate_release_gate, write_release_gate_summary


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_evaluate_release_gate_ready(tmp_path: Path) -> None:
    ubuntu = _write_json(
        tmp_path / "ubuntu.json",
        {
            "supported_target": "Ubuntu standalone",
            "environment_ok": True,
            "overall_ok": True,
            "interface_check": {"present": True},
            "hardware_qualification": [{"area": "capture_adapter", "status": "supported"}],
            "processing_smoke": {
                "success": True,
                "selected_protocol_support": {"replay_level": "guaranteed"},
                "analysis_preflight": {"replay": {"status": "ready"}},
            },
        },
    )
    pi = _write_json(
        tmp_path / "pi.json",
        {
            "supported_target": "Raspberry Pi OS standalone",
            "environment_ok": True,
            "overall_ok": True,
            "interface_check": {"present": True},
            "hardware_qualification": [{"area": "capture_adapter", "status": "supported_with_limits"}],
            "processing_smoke": {
                "success": True,
                "selected_protocol_support": {"replay_level": "high_confidence"},
                "analysis_preflight": {"replay": {"status": "ready"}},
            },
        },
    )
    windows = _write_json(
        tmp_path / "windows.json",
        {
            "supported_target": "Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture",
            "environment_ok": True,
            "overall_ok": True,
            "doctor": {
                "ok": True,
                "remote": {"service": True, "privileged_runner": True, "privilege_mode": "sudoers_runner"},
            },
            "hardware_qualification": [
                {"area": "host", "status": "supported"},
                {"area": "capture_node", "status": "supported_with_limits"},
            ],
        },
    )
    sample = _write_json(
        tmp_path / "sample.json",
        {
            "selected_protocol_support": {"replay_level": "guaranteed"},
            "feasibility": {"replay": {"status": "ready"}},
            "candidate_material": {"mode": "static_xor_candidate"},
        },
    )

    result = evaluate_release_gate(
        ubuntu_report=ubuntu,
        pi_report=pi,
        windows_report=windows,
        sample_reports=[sample],
    )

    assert result["fully_validated"] is True
    assert result["status"] == "ready"


def test_evaluate_release_gate_blocks_without_sample_reports(tmp_path: Path) -> None:
    report = _write_json(
        tmp_path / "report.json",
        {
            "supported_target": "Ubuntu standalone",
            "environment_ok": True,
            "overall_ok": True,
            "interface_check": {"present": True},
            "hardware_qualification": [{"area": "capture_adapter", "status": "supported"}],
            "processing_smoke": {
                "success": True,
                "selected_protocol_support": {"replay_level": "guaranteed"},
                "analysis_preflight": {"replay": {"status": "ready"}},
            },
        },
    )
    windows = _write_json(
        tmp_path / "windows.json",
        {
            "supported_target": "Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture",
            "environment_ok": True,
            "overall_ok": True,
            "doctor": {"ok": True, "remote": {"service": True}},
            "hardware_qualification": [{"area": "host", "status": "supported"}, {"area": "capture_node", "status": "supported"}],
        },
    )

    result = evaluate_release_gate(
        ubuntu_report=report,
        pi_report=report,
        windows_report=windows,
        sample_reports=[],
    )

    assert result["fully_validated"] is False
    assert result["status"] == "blocked"


def test_write_release_gate_summary(tmp_path: Path) -> None:
    path = write_release_gate_summary({"status": "ready", "fully_validated": True}, tmp_path / "summary.json")
    assert path.exists()
