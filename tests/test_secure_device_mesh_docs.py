from pathlib import Path


def test_secure_device_mesh_phase_one_documents_required_threat_model() -> None:
    text = Path("docs/SECURE_DEVICE_MESH.md").read_text(encoding="utf-8")

    required_sections = [
        "## Phase 1 status",
        "## Phase 2 status",
        "## Phase 3 status",
        "## Phase 4 status",
        "## Phase 5 status",
        "## Phase 6 status",
        "## Phase 7 status",
        "## Phase 8 status",
        "## Phase 9 status",
        "## Protected assets",
        "## Security goals",
        "## Non-goals",
        "## Roles",
        "## Trust boundaries",
        "## Adversary model",
        "## Mandatory rules",
        "## Minimum acceptance checks",
    ]
    for section in required_sections:
        assert section in text

    required_rules = [
        "No custom cipher",
        "No command execution from discovery traffic",
        "No secret material in dashboard HTML",
        "No trust based only on IP address",
        "No nonce reuse for the same encryption key",
        "No storing private device keys in `lab.json`",
        "No accepting an encrypted command without checking sender",
    ]
    for rule in required_rules:
        assert rule in text
