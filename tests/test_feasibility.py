from __future__ import annotations

from wifi_pipeline.feasibility import (
    evaluate_pipeline_feasibility,
    evaluate_replay_feasibility,
    evaluate_wpa_feasibility,
)


def test_evaluate_pipeline_feasibility_blocks_without_report() -> None:
    result = evaluate_pipeline_feasibility({}, None)

    assert result["status"] == "blocked"
    assert result["replay"]["status"] == "blocked"


def test_evaluate_replay_feasibility_ready_for_supported_text_stream() -> None:
    report = {
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "score": 100,
            "byte_count": 4096,
            "unit_type_counts": {"plain_text": 4},
        },
        "selected_protocol_support": {
            "dominant_unit_type": "plain_text",
            "decode_level": "guaranteed",
            "replay_level": "guaranteed",
            "detail": "supported text",
        },
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
    }

    result = evaluate_replay_feasibility({"min_candidate_bytes": 1024}, report)

    assert result["status"] == "ready"
    assert result["blockers"] == []


def test_evaluate_replay_feasibility_blocks_unsupported_family() -> None:
    report = {
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "score": 80,
            "byte_count": 4096,
            "unit_type_counts": {"opaque_chunk": 3},
        },
        "selected_protocol_support": {
            "dominant_unit_type": "opaque_chunk",
            "decode_level": "heuristic",
            "replay_level": "unsupported",
            "detail": "opaque replay is unsupported",
        },
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
    }

    result = evaluate_replay_feasibility({"min_candidate_bytes": 1024}, report)

    assert result["status"] == "blocked"
    assert "opaque replay is unsupported" in result["blockers"][0]


def test_evaluate_wpa_feasibility_not_applicable_without_wifi_context() -> None:
    result = evaluate_wpa_feasibility({"output_dir": "."})

    assert result["status"] == "ready"
    assert result["state"] == "not_applicable"
