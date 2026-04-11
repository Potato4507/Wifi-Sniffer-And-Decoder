from __future__ import annotations

import json

import pytest

from wifi_pipeline import secure_mesh as secure_mesh_module
from wifi_pipeline.secure_mesh import (
    MeshDeviceRecord,
    MeshDiscoveryRecord,
    MeshReplayCache,
    MeshRegistry,
    MeshTransportHint,
    default_private_dir,
    default_registry_path,
    discover_mesh_devices,
    fingerprint_for_public_material,
    generate_local_identity,
    generate_pairing_token,
    identity_path,
    import_pairing_bundle,
    init_wireguard_identity,
    init_registry,
    load_local_identity,
    load_mesh_command_bundle,
    load_mesh_discovery_hint_file,
    load_pairing_bundle,
    load_wireguard_identity,
    mesh_paths_for_device,
    mesh_command_bundle_summary,
    open_mesh_command,
    pairing_token_hash,
    parse_mesh_transport_hint,
    redact_public_payload,
    render_wireguard_config,
    seal_mesh_command,
    select_mesh_route,
    wireguard_identity_path,
    write_mesh_command_bundle,
    write_pairing_bundle,
)


def _device(device_id: str = "raspi-sniffer", role: str = "capture_appliance") -> MeshDeviceRecord:
    return MeshDeviceRecord.create(
        device_id=device_id,
        role=role,
        public_identity_key=f"{device_id}-identity-public",
        public_encryption_key=f"{device_id}-encryption-public",
        allowed_tunnel_ip="10.77.0.2/32",
    )


def _paired_mesh_config(tmp_path):
    config = {
        "secure_mesh_private_dir": str(tmp_path / "private"),
        "secure_mesh_registry_path": str(tmp_path / "devices.json"),
        "secure_mesh_replay_cache_path": str(tmp_path / "replay_cache.json"),
    }
    controller = generate_local_identity(config, device_id="controller", role="controller")
    raspi = generate_local_identity(config, device_id="raspi-sniffer", role="capture_appliance")
    registry = init_registry(config)
    registry.add_device(controller.to_public_record())
    registry.add_device(raspi.to_public_record())
    registry.save()
    return config, controller, raspi


def test_mesh_registry_round_trips_public_device_records(tmp_path) -> None:
    registry_path = tmp_path / "mesh" / "devices.json"
    registry = MeshRegistry.load(registry_path)
    registry.add_device(_device())

    registry.save()
    loaded = MeshRegistry.load(registry_path)
    record = loaded.get_device("raspi-sniffer")

    assert record is not None
    assert record.role == "capture_appliance"
    assert record.allowed_tunnel_ip == "10.77.0.2/32"
    assert record.fingerprint == _device().fingerprint
    assert loaded.is_authorized("raspi-sniffer", "capture.artifact.send")
    assert not loaded.is_authorized("raspi-sniffer", "capture.start")

    raw = json.loads(registry_path.read_text(encoding="utf-8"))
    serialized = json.dumps(raw)
    assert "private_key" not in serialized
    assert "pairing_token" not in serialized
    assert raw["protocol"] == "wifi-pipeline-secure/v1"


def test_mesh_registry_revoke_blocks_authorization(tmp_path) -> None:
    registry = MeshRegistry.load(tmp_path / "devices.json")
    registry.add_device(_device())

    assert registry.is_authorized("raspi-sniffer", "capture.artifact.send")

    registry.revoke("raspi-sniffer", when_utc="2026-04-10T00:00:00Z")

    assert not registry.is_authorized("raspi-sniffer", "capture.artifact.send")
    assert registry.get_device("raspi-sniffer").revoked is True  # type: ignore[union-attr]
    assert registry.get_device("raspi-sniffer").metadata["revoked_at_utc"] == "2026-04-10T00:00:00Z"  # type: ignore[union-attr]


def test_mesh_registry_rejects_secret_fields(tmp_path) -> None:
    registry_path = tmp_path / "devices.json"
    registry_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "devices": {
                    "bad": {
                        "device_id": "bad",
                        "role": "capture_appliance",
                        "public_identity_key": "id",
                        "public_encryption_key": "enc",
                        "fingerprint": "",
                        "private_key": "do-not-store",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="secret field"):
        MeshRegistry.load(registry_path)


def test_mesh_role_permissions_prevent_escalation() -> None:
    with pytest.raises(ValueError, match="cannot be granted"):
        MeshDeviceRecord.create(
            device_id="pi",
            role="capture_appliance",
            public_identity_key="id-public",
            public_encryption_key="enc-public",
            allowed_actions=["config.update"],
        )


def test_mesh_fingerprint_is_stable_and_human_checkable() -> None:
    first = fingerprint_for_public_material("device", "role", "identity", "encryption")
    second = fingerprint_for_public_material("device", "role", "identity", "encryption")
    changed = fingerprint_for_public_material("device", "role", "identity", "other")

    assert first == second
    assert first != changed
    assert "-" in first
    assert first.upper() == first


def test_mesh_redaction_scrubs_nested_secret_fields() -> None:
    payload = {
        "device_id": "controller",
        "public_identity_key": "safe",
        "secure_mesh_private_key": "secret",
        "nested": {"pairing_token": "token", "status": "ok"},
    }

    redacted = redact_public_payload(payload)

    assert redacted["public_identity_key"] == "safe"
    assert redacted["secure_mesh_private_key"] == "[redacted]"
    assert redacted["nested"]["pairing_token"] == "[redacted]"
    assert redacted["nested"]["status"] == "ok"


def test_mesh_default_paths_keep_private_material_outside_lab_json(tmp_path) -> None:
    config = {
        "output_dir": str(tmp_path / "pipeline_output"),
        "secure_mesh_registry_path": str(tmp_path / "pipeline_output" / "secure_mesh" / "devices.json"),
    }

    registry = init_registry(config)

    assert registry.path == default_registry_path(config)
    assert registry.path.exists()
    assert default_private_dir({}).name == "secure_mesh"
    assert "lab.json" not in str(default_private_dir({})).lower()


def test_mesh_generate_local_identity_writes_private_keys_outside_registry(tmp_path) -> None:
    config = {
        "secure_mesh_private_dir": str(tmp_path / "private"),
        "secure_mesh_registry_path": str(tmp_path / "public" / "devices.json"),
    }

    identity = generate_local_identity(config, device_id="controller", role="controller")
    loaded = load_local_identity(config, device_id="controller")
    registry = init_registry(config)
    registry.add_device(identity.to_public_record())
    registry.save()

    private_file = identity_path(config, device_id="controller")
    registry_text = registry.path.read_text(encoding="utf-8")

    assert private_file.exists()
    assert loaded.fingerprint == identity.fingerprint
    assert identity.public_identity_key.startswith("ed25519:")
    assert identity.public_encryption_key.startswith("x25519:")
    assert "PRIVATE KEY" in private_file.read_text(encoding="utf-8")
    assert "PRIVATE KEY" not in registry_text
    assert "identity_private_key_pem" not in registry_text


def test_mesh_generate_local_identity_refuses_overwrite_without_flag(tmp_path) -> None:
    config = {"secure_mesh_private_dir": str(tmp_path / "private")}
    generate_local_identity(config, device_id="controller", role="controller")

    with pytest.raises(FileExistsError):
        generate_local_identity(config, device_id="controller", role="controller")

    replaced = generate_local_identity(config, device_id="controller", role="controller", overwrite=True)

    assert replaced.device_id == "controller"


def test_mesh_pairing_bundle_import_requires_verified_fingerprint(tmp_path) -> None:
    source_config = {"secure_mesh_private_dir": str(tmp_path / "source_private")}
    target_config = {"secure_mesh_registry_path": str(tmp_path / "target" / "devices.json")}
    identity = generate_local_identity(source_config, device_id="raspi-sniffer", role="capture_appliance")
    bundle_path = tmp_path / "raspi.bundle.json"

    write_pairing_bundle(identity, bundle_path, allowed_tunnel_ip="10.77.0.2/32")
    bundle_record = load_pairing_bundle(bundle_path)

    assert bundle_record.device_id == "raspi-sniffer"
    assert bundle_record.fingerprint == identity.fingerprint

    with pytest.raises(ValueError, match="expected fingerprint"):
        import_pairing_bundle(target_config, bundle_path=bundle_path, expected_fingerprint="")

    with pytest.raises(ValueError, match="does not match"):
        import_pairing_bundle(target_config, bundle_path=bundle_path, expected_fingerprint="WRONG")

    imported = import_pairing_bundle(
        target_config,
        bundle_path=bundle_path,
        expected_fingerprint=identity.fingerprint,
    )

    assert imported.device_id == "raspi-sniffer"
    assert MeshRegistry.load(default_registry_path(target_config)).get_device("raspi-sniffer") is not None
    assert "PRIVATE KEY" not in bundle_path.read_text(encoding="utf-8")


def test_mesh_pairing_token_hash_is_context_bound() -> None:
    token = generate_pairing_token()
    same = pairing_token_hash(token, "device-a", "fingerprint")
    again = pairing_token_hash(token, "device-a", "fingerprint")
    changed = pairing_token_hash(token, "device-b", "fingerprint")

    assert len(token) >= 22
    assert same == again
    assert same != changed


def test_mesh_command_envelope_round_trips_json_body(tmp_path) -> None:
    config, _controller, _raspi = _paired_mesh_config(tmp_path)

    envelope = seal_mesh_command(
        config,
        sender_device_id="controller",
        receiver_device_id="raspi-sniffer",
        command="capture.start",
        body={"duration": 5, "interface": "wlan0"},
        counter=1,
        message_id="cmd-1",
    )
    cache = MeshReplayCache(path=tmp_path / "replay_cache.json")
    opened, body = open_mesh_command(
        config,
        envelope.to_dict(),
        receiver_device_id="raspi-sniffer",
        replay_cache=cache,
    )
    cache.save()

    assert opened.message_id == "cmd-1"
    assert body == {"duration": 5, "interface": "wlan0"}
    assert "wlan0" not in json.dumps(envelope.to_dict())
    assert MeshReplayCache.load(tmp_path / "replay_cache.json").seen_message_ids == {"cmd-1"}


def test_mesh_command_operator_approval_round_trips_without_leaking_code(tmp_path) -> None:
    config, _controller, _raspi = _paired_mesh_config(tmp_path)
    approval_code = "phase8-approval"

    envelope = seal_mesh_command(
        config,
        sender_device_id="controller",
        receiver_device_id="raspi-sniffer",
        command="capture.start",
        body={"duration": 10},
        counter=1,
        message_id="approved-1",
        approval_code=approval_code,
    )

    assert approval_code not in json.dumps(envelope.to_dict())

    opened, body = open_mesh_command(
        config,
        envelope.to_dict(),
        receiver_device_id="raspi-sniffer",
        approval_code=approval_code,
        require_approval=True,
    )

    assert opened.message_id == "approved-1"
    assert body == {"duration": 10}

    with pytest.raises(ValueError, match="approval verification failed"):
        open_mesh_command(
            config,
            envelope.to_dict(),
            receiver_device_id="raspi-sniffer",
            approval_code="wrong",
            require_approval=True,
        )

    cache = MeshReplayCache()
    with pytest.raises(ValueError, match="approval verification failed"):
        open_mesh_command(
            config,
            envelope.to_dict(),
            receiver_device_id="raspi-sniffer",
            approval_code="wrong",
            require_approval=True,
            replay_cache=cache,
        )
    _opened, replay_body = open_mesh_command(
        config,
        envelope.to_dict(),
        receiver_device_id="raspi-sniffer",
        approval_code=approval_code,
        require_approval=True,
        replay_cache=cache,
    )

    assert replay_body == {"duration": 10}
    assert cache.seen_message_ids == {"approved-1"}


def test_mesh_command_required_sensitive_approval_rejects_unapproved_body(tmp_path) -> None:
    config, _controller, _raspi = _paired_mesh_config(tmp_path)
    config["secure_mesh_require_approval_for_sensitive"] = True
    envelope = seal_mesh_command(
        config,
        sender_device_id="controller",
        receiver_device_id="raspi-sniffer",
        command="capture.start",
        body={"duration": 5},
        counter=1,
        message_id="needs-approval",
    )

    with pytest.raises(ValueError, match="requires operator approval"):
        open_mesh_command(config, envelope.to_dict(), receiver_device_id="raspi-sniffer")

    status = seal_mesh_command(
        config,
        sender_device_id="controller",
        receiver_device_id="raspi-sniffer",
        command="doctor.run",
        body={},
        counter=2,
        message_id="doctor-no-approval",
    )
    _opened, body = open_mesh_command(config, status.to_dict(), receiver_device_id="raspi-sniffer")

    assert body == {}


def test_mesh_command_bundle_round_trips_envelope_metadata(tmp_path) -> None:
    config, _controller, _raspi = _paired_mesh_config(tmp_path)
    first = seal_mesh_command(
        config,
        sender_device_id="controller",
        receiver_device_id="raspi-sniffer",
        command="capture.start",
        body={"duration": 1},
        counter=1,
        message_id="bundle-1",
    )
    second = seal_mesh_command(
        config,
        sender_device_id="controller",
        receiver_device_id="raspi-sniffer",
        command="doctor.run",
        body={},
        counter=2,
        message_id="bundle-2",
    )
    bundle_path = tmp_path / "commands.bundle.json"

    written = write_mesh_command_bundle([first, second.to_dict()], bundle_path, route_hint="serial:COM4")
    loaded = load_mesh_command_bundle(written)
    summary = mesh_command_bundle_summary(loaded)

    assert [item["message_id"] for item in summary] == ["bundle-1", "bundle-2"]
    assert "duration" not in bundle_path.read_text(encoding="utf-8")
    assert "serial:COM4" in bundle_path.read_text(encoding="utf-8")


def test_mesh_command_envelope_rejects_tampering_wrong_receiver_and_expiry(tmp_path) -> None:
    config, _controller, _raspi = _paired_mesh_config(tmp_path)
    envelope = seal_mesh_command(
        config,
        sender_device_id="controller",
        receiver_device_id="raspi-sniffer",
        command="capture.start",
        body={"duration": 5},
        counter=1,
        message_id="cmd-1",
    )
    tampered = envelope.to_dict()
    tampered["ciphertext"] = str(tampered["ciphertext"])[:-1] + (
        "A" if not str(tampered["ciphertext"]).endswith("A") else "B"
    )

    with pytest.raises(ValueError, match="signature verification failed"):
        open_mesh_command(config, tampered, receiver_device_id="raspi-sniffer")

    with pytest.raises(ValueError, match="receiver mismatch"):
        open_mesh_command(config, envelope.to_dict(), receiver_device_id="controller")

    expired = seal_mesh_command(
        config,
        sender_device_id="controller",
        receiver_device_id="raspi-sniffer",
        command="capture.start",
        body={},
        counter=2,
        ttl_seconds=1,
        message_id="expired",
        created_at_utc="2026-04-10T00:00:00Z",
    )
    with pytest.raises(ValueError, match="expired"):
        open_mesh_command(config, expired.to_dict(), receiver_device_id="raspi-sniffer", now=2_000_000_000)


def test_mesh_command_replay_cache_rejects_replayed_message_and_old_counter(tmp_path) -> None:
    config, _controller, _raspi = _paired_mesh_config(tmp_path)
    cache = MeshReplayCache()
    first = seal_mesh_command(
        config,
        sender_device_id="controller",
        receiver_device_id="raspi-sniffer",
        command="capture.start",
        body={},
        counter=5,
        message_id="cmd-5",
    )

    open_mesh_command(config, first.to_dict(), receiver_device_id="raspi-sniffer", replay_cache=cache)

    with pytest.raises(ValueError, match="message_id"):
        open_mesh_command(config, first.to_dict(), receiver_device_id="raspi-sniffer", replay_cache=cache)

    old_counter = seal_mesh_command(
        config,
        sender_device_id="controller",
        receiver_device_id="raspi-sniffer",
        command="capture.start",
        body={},
        counter=4,
        message_id="cmd-4",
    )
    with pytest.raises(ValueError, match="counter"):
        open_mesh_command(config, old_counter.to_dict(), receiver_device_id="raspi-sniffer", replay_cache=cache)


def test_mesh_command_replay_cache_rejects_nonce_reuse(tmp_path, monkeypatch) -> None:
    config, _controller, _raspi = _paired_mesh_config(tmp_path)
    monkeypatch.setattr(secure_mesh_module.secrets, "token_bytes", lambda size: b"\x11" * size)
    first = seal_mesh_command(
        config,
        sender_device_id="controller",
        receiver_device_id="raspi-sniffer",
        command="capture.start",
        body={},
        counter=1,
        message_id="nonce-1",
    )
    second = seal_mesh_command(
        config,
        sender_device_id="controller",
        receiver_device_id="raspi-sniffer",
        command="capture.start",
        body={},
        counter=2,
        message_id="nonce-2",
    )
    cache = MeshReplayCache()

    assert first.nonce == second.nonce
    open_mesh_command(config, first.to_dict(), receiver_device_id="raspi-sniffer", replay_cache=cache)
    with pytest.raises(ValueError, match="nonce"):
        open_mesh_command(config, second.to_dict(), receiver_device_id="raspi-sniffer", replay_cache=cache)


def test_mesh_command_envelope_rejects_unauthorized_and_revoked_senders(tmp_path) -> None:
    config, _controller, _raspi = _paired_mesh_config(tmp_path)

    with pytest.raises(ValueError, match="not authorized"):
        seal_mesh_command(
            config,
            sender_device_id="raspi-sniffer",
            receiver_device_id="controller",
            command="capture.start",
            body={},
            counter=1,
        )

    registry = MeshRegistry.load(default_registry_path(config))
    registry.revoke("controller", when_utc="2026-04-10T00:00:00Z")
    registry.save()

    with pytest.raises(ValueError, match="revoked"):
        seal_mesh_command(
            config,
            sender_device_id="controller",
            receiver_device_id="raspi-sniffer",
            command="capture.start",
            body={},
            counter=1,
        )


def test_mesh_discovery_trusts_matching_fingerprint_and_ranks_routes(tmp_path) -> None:
    registry_path = tmp_path / "devices.json"
    registry = MeshRegistry.load(registry_path)
    paired = MeshDeviceRecord.create(
        device_id="raspi-sniffer",
        role="capture_appliance",
        public_identity_key="id-public",
        public_encryption_key="enc-public",
        allowed_tunnel_ip="10.77.0.2/32",
        transport_hints={"ssh": "david@raspi-sniffer", "wireguard": "10.77.0.2"},
    )
    registry.add_device(paired)
    registry.save()

    records = discover_mesh_devices(
        {"secure_mesh_registry_path": str(registry_path)},
        appliance_nodes=[
            {
                "host": "raspi-sniffer",
                "ssh_target": "david@raspi-sniffer",
                "health_endpoint": "http://raspi-sniffer:8741/health",
                "secure_mesh_device_id": "raspi-sniffer",
                "secure_mesh_fingerprint": paired.fingerprint,
                "wireguard_endpoint": "10.77.0.2",
            }
        ],
    )
    trusted = [record for record in records if record.source == "appliance_discovery"][0]

    assert trusted.trusted is True
    assert trusted.trust_status == "trusted"
    assert trusted.matched_device_id == "raspi-sniffer"
    assert trusted.best_transport().transport_type == "wireguard"  # type: ignore[union-attr]


def test_mesh_discovery_accepts_transport_independent_operator_hints(tmp_path) -> None:
    registry_path = tmp_path / "devices.json"
    registry = MeshRegistry.load(registry_path)
    paired = MeshDeviceRecord.create(
        device_id="raspi-sniffer",
        role="capture_appliance",
        public_identity_key="id-public",
        public_encryption_key="enc-public",
        transport_hints={"bluetooth": "AA:BB:CC:DD", "serial": "COM4", "radio": "lora:raspi"},
    )
    registry.add_device(paired)
    registry.save()

    records = discover_mesh_devices(
        {"secure_mesh_registry_path": str(registry_path)},
        appliance_nodes=[],
        include_registry=False,
        transport_hints=[
            parse_mesh_transport_hint(
                "bluetooth=AA:BB:CC:DD",
                device_id_hint="raspi-sniffer",
            )
        ],
    )
    hinted = records[0]

    assert hinted.source == "operator_hint"
    assert hinted.trusted is False
    assert hinted.trust_status in ("known_device_id_hint", "known_route_hint")
    assert hinted.best_transport().transport_type == "bluetooth"  # type: ignore[union-attr]

    trusted_records = discover_mesh_devices(
        {"secure_mesh_registry_path": str(registry_path)},
        appliance_nodes=[],
        include_registry=False,
        transport_hints=[
            parse_mesh_transport_hint(
                "serial=COM4",
                fingerprint_hint=paired.fingerprint,
            )
        ],
    )
    trusted = trusted_records[0]

    assert trusted.trusted is True
    assert trusted.trust_status == "trusted"
    assert trusted.matched_device_id == "raspi-sniffer"
    assert trusted.best_transport().transport_type == "serial"  # type: ignore[union-attr]


def test_mesh_route_selection_prefers_trusted_high_priority_transport(tmp_path) -> None:
    registry_path = tmp_path / "devices.json"
    registry = MeshRegistry.load(registry_path)
    paired = MeshDeviceRecord.create(
        device_id="raspi-sniffer",
        role="capture_appliance",
        public_identity_key="id-public",
        public_encryption_key="enc-public",
        transport_hints={"ssh": "david@raspi-sniffer", "wireguard": "10.77.0.2", "serial": "COM4"},
    )
    registry.add_device(paired)
    registry.save()
    records = discover_mesh_devices({"secure_mesh_registry_path": str(registry_path)}, appliance_nodes=[])

    plan = select_mesh_route(records, "raspi-sniffer")
    serial_plan = select_mesh_route(records, "raspi-sniffer", allowed_transports=["serial"])

    assert plan.selected is True
    assert plan.transport is not None
    assert plan.transport.transport_type == "wireguard"
    assert serial_plan.selected is True
    assert serial_plan.transport is not None
    assert serial_plan.transport.transport_type == "serial"


def test_mesh_route_selection_rejects_untrusted_hints_by_default(tmp_path) -> None:
    registry_path = tmp_path / "devices.json"
    registry = MeshRegistry.load(registry_path)
    registry.add_device(_device())
    registry.save()
    records = discover_mesh_devices(
        {"secure_mesh_registry_path": str(registry_path)},
        appliance_nodes=[],
        include_registry=False,
        transport_hints=[parse_mesh_transport_hint("bluetooth=AA:BB:CC", device_id_hint="raspi-sniffer")],
    )

    trusted_plan = select_mesh_route(records, "raspi-sniffer")
    staging_plan = select_mesh_route(records, "raspi-sniffer", require_trusted=False)

    assert trusted_plan.selected is False
    assert "trusted" in trusted_plan.reason
    assert staging_plan.selected is True
    assert staging_plan.transport is not None
    assert staging_plan.transport.transport_type == "bluetooth"


def test_mesh_route_selection_rejects_revoked_records() -> None:
    records = [
        MeshDiscoveryRecord(
            source="operator_hint",
            device_id_hint="raspi-sniffer",
            matched_device_id="raspi-sniffer",
            trusted=True,
            trust_status="revoked",
            revoked=True,
            transports=[MeshTransportHint("serial", "COM4", status="detected")],
        )
    ]

    plan = select_mesh_route(records, "raspi-sniffer")

    assert plan.selected is False
    assert plan.transport is None
    assert "No usable route" in plan.reason


@pytest.mark.parametrize("hint", ["bluetooth", "unknown=target", "serial="])
def test_mesh_transport_hint_validation_rejects_bad_operator_input(hint: str) -> None:
    with pytest.raises(ValueError):
        parse_mesh_transport_hint(hint)


def test_mesh_discovery_loads_hint_files_and_rejects_secrets(tmp_path) -> None:
    registry_path = tmp_path / "devices.json"
    registry = MeshRegistry.load(registry_path)
    paired = _device()
    registry.add_device(paired)
    registry.save()
    hints_path = tmp_path / "mesh-hints.json"
    hints_path.write_text(
        json.dumps(
            {
                "hints": [
                    {
                        "transport_type": "hotspot",
                        "target": "WifiPipeline-Raspi",
                        "fingerprint": paired.fingerprint,
                    },
                    {
                        "serial_path": "COM4",
                        "secure_mesh_device_id": "raspi-sniffer",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    loaded = load_mesh_discovery_hint_file(hints_path)
    records = discover_mesh_devices(
        {"secure_mesh_registry_path": str(registry_path)},
        appliance_nodes=[],
        include_registry=False,
        hint_files=[str(hints_path)],
    )

    assert len(loaded) == 2
    assert any(record.trusted and record.best_transport().transport_type == "hotspot" for record in records)  # type: ignore[union-attr]
    assert any(record.trust_status == "known_device_id_hint" for record in records)

    bom_path = tmp_path / "bom-hints.json"
    bom_path.write_bytes(b"\xef\xbb\xbf" + json.dumps([{"transport": "serial", "target": "COM5"}]).encode("utf-8"))
    assert load_mesh_discovery_hint_file(bom_path)[0]["target"] == "COM5"

    bad_path = tmp_path / "bad-hints.json"
    bad_path.write_text(json.dumps({"hints": [{"transport": "serial", "target": "COM4", "private_key": "nope"}]}), encoding="utf-8")

    with pytest.raises(ValueError, match="secret field"):
        load_mesh_discovery_hint_file(bad_path)


def test_mesh_discovery_appliance_records_include_phase_seven_transports(tmp_path) -> None:
    registry_path = tmp_path / "devices.json"
    registry = MeshRegistry.load(registry_path)
    paired = _device()
    registry.add_device(paired)
    registry.save()

    records = discover_mesh_devices(
        {"secure_mesh_registry_path": str(registry_path)},
        appliance_nodes=[
            {
                "secure_mesh_fingerprint": paired.fingerprint,
                "secure_mesh_device_id": "raspi-sniffer",
                "bluetooth_id": "AA:BB:CC:DD",
                "serial_path": "COM4",
                "ethernet_host": "192.168.50.10",
                "radio": "lora:raspi",
            }
        ],
        include_registry=False,
    )
    discovered = records[0]
    transport_types = {transport.transport_type for transport in discovered.transports}

    assert discovered.trusted is True
    assert {"bluetooth", "serial", "ethernet", "radio"}.issubset(transport_types)
    assert discovered.trust_reason.startswith("Fingerprint matches")


def test_mesh_discovery_does_not_trust_name_without_fingerprint(tmp_path) -> None:
    registry_path = tmp_path / "devices.json"
    registry = MeshRegistry.load(registry_path)
    registry.add_device(_device())
    registry.save()

    records = discover_mesh_devices(
        {"secure_mesh_registry_path": str(registry_path)},
        appliance_nodes=[
            {
                "host": "evil.local",
                "ssh_target": "pi@evil.local",
                "device_name": "raspi-sniffer",
                "health_endpoint": "http://evil.local:8741/health",
            }
        ],
    )
    discovered = [record for record in records if record.source == "appliance_discovery"][0]

    assert discovered.trusted is False
    assert discovered.trust_status in ("known_device_id_hint", "untrusted")
    assert "fingerprint" in discovered.trust_reason.lower()


def test_mesh_discovery_marks_revoked_fingerprint_as_untrusted(tmp_path) -> None:
    registry_path = tmp_path / "devices.json"
    registry = MeshRegistry.load(registry_path)
    record = _device()
    registry.add_device(record)
    registry.revoke(record.device_id, when_utc="2026-04-10T00:00:00Z")
    registry.save()

    records = discover_mesh_devices(
        {"secure_mesh_registry_path": str(registry_path)},
        appliance_nodes=[
            {
                "host": "raspi-sniffer",
                "ssh_target": "david@raspi-sniffer",
                "secure_mesh_fingerprint": record.fingerprint,
            }
        ],
    )
    discovered = [item for item in records if item.source == "appliance_discovery"][0]

    assert discovered.trusted is False
    assert discovered.revoked is True
    assert discovered.trust_status == "revoked"


def test_mesh_paths_for_device_filters_discovery_records() -> None:
    records = [
        MeshDiscoveryRecord(
            source="registry",
            device_id_hint="raspi-sniffer",
            matched_device_id="raspi-sniffer",
            trusted=True,
            transports=[MeshTransportHint("ssh", "david@raspi-sniffer")],
        ),
        MeshDiscoveryRecord(
            source="registry",
            device_id_hint="other",
            matched_device_id="other",
            trusted=True,
            transports=[MeshTransportHint("ssh", "other@host")],
        ),
    ]

    filtered = mesh_paths_for_device(records, "raspi-sniffer")

    assert len(filtered) == 1
    assert filtered[0].matched_device_id == "raspi-sniffer"


def test_mesh_wireguard_init_updates_registry_without_leaking_private_key(tmp_path) -> None:
    config = {
        "secure_mesh_private_dir": str(tmp_path / "private"),
        "secure_mesh_registry_path": str(tmp_path / "devices.json"),
    }
    identity = generate_local_identity(config, device_id="controller", role="controller")
    registry = init_registry(config)
    registry.add_device(identity.to_public_record())
    registry.save()

    wg = init_wireguard_identity(
        config,
        device_id="controller",
        address="10.77.0.1/24",
        listen_port=51820,
        endpoint="controller.example:51820",
    )
    loaded = load_wireguard_identity(config, device_id="controller")
    record = MeshRegistry.load(default_registry_path(config)).get_device("controller")
    registry_text = default_registry_path(config).read_text(encoding="utf-8")

    assert wireguard_identity_path(config, device_id="controller").exists()
    assert loaded.public_key == wg.public_key
    assert record is not None
    assert record.metadata["wireguard_public_key"] == wg.public_key
    assert record.allowed_tunnel_ip == "10.77.0.1/32"
    assert record.transport_hints["wireguard_endpoint"] == "controller.example:51820"
    assert wg.private_key not in registry_text
    assert "private_key" not in registry_text


def test_mesh_render_wireguard_config_for_paired_peer(tmp_path) -> None:
    config = {
        "secure_mesh_private_dir": str(tmp_path / "private"),
        "secure_mesh_registry_path": str(tmp_path / "devices.json"),
    }
    controller = generate_local_identity(config, device_id="controller", role="controller")
    raspi = generate_local_identity(config, device_id="raspi-sniffer", role="capture_appliance")
    registry = init_registry(config)
    registry.add_device(controller.to_public_record())
    registry.add_device(raspi.to_public_record())
    registry.save()
    controller_wg = init_wireguard_identity(config, device_id="controller", address="10.77.0.1/24")
    raspi_wg = init_wireguard_identity(
        config,
        device_id="raspi-sniffer",
        address="10.77.0.2/24",
        endpoint="raspi-sniffer:51820",
    )

    rendered = render_wireguard_config(config, device_id="controller", peer_device_id="raspi-sniffer")

    assert "[Interface]" in rendered
    assert f"PrivateKey = {controller_wg.private_key}" in rendered
    assert "Address = 10.77.0.1/24" in rendered
    assert "[Peer]" in rendered
    assert "AllowedIPs = 10.77.0.2/32" in rendered
    assert f"PublicKey = {raspi_wg.public_key}" in rendered
    assert "Endpoint = raspi-sniffer:51820" in rendered


def test_mesh_render_wireguard_config_requires_peer_public_key(tmp_path) -> None:
    config = {
        "secure_mesh_private_dir": str(tmp_path / "private"),
        "secure_mesh_registry_path": str(tmp_path / "devices.json"),
    }
    controller = generate_local_identity(config, device_id="controller", role="controller")
    peer = MeshDeviceRecord.create(
        device_id="peer",
        role="capture_appliance",
        public_identity_key="peer-id",
        public_encryption_key="peer-enc",
        allowed_tunnel_ip="10.77.0.2/32",
    )
    registry = init_registry(config)
    registry.add_device(controller.to_public_record())
    registry.add_device(peer)
    registry.save()
    init_wireguard_identity(config, device_id="controller", address="10.77.0.1/24")

    with pytest.raises(ValueError, match="WireGuard public key"):
        render_wireguard_config(config, device_id="controller", peer_device_id="peer")


def test_mesh_pairing_bundle_export_includes_wireguard_public_metadata(tmp_path) -> None:
    config = {
        "secure_mesh_private_dir": str(tmp_path / "private"),
        "secure_mesh_registry_path": str(tmp_path / "devices.json"),
    }
    identity = generate_local_identity(config, device_id="controller", role="controller")
    registry = init_registry(config)
    registry.add_device(identity.to_public_record())
    registry.save()
    wg = init_wireguard_identity(config, device_id="controller", address="10.77.0.1/24")
    bundle_path = tmp_path / "controller.bundle.json"

    write_pairing_bundle(
        identity,
        bundle_path,
        allowed_tunnel_ip="10.77.0.1/32",
        transport_hints={"wireguard": "10.77.0.1/24"},
        metadata={"wireguard_public_key": wg.public_key},
    )
    record = load_pairing_bundle(bundle_path)

    assert record.metadata["wireguard_public_key"] == wg.public_key
    assert "private_key" not in bundle_path.read_text(encoding="utf-8")
