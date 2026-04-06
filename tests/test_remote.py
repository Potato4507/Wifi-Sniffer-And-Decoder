from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from wifi_pipeline.remote import (
    _bootstrap_remote_script,
    _appliance_profile_script,
    _capture_agent_script,
    _ensure_public_key,
    _extract_capture_path,
    _escape_remote,
    _is_pattern,
    _latest_patterns,
    _parse_key_value_output,
    _privileged_capture_runner_script,
    _resolve_remote_install_mode,
    _resolve_remote_install_profile,
    bootstrap_remote_host,
    discover_remote_appliances,
    doctor_remote_host,
    pair_remote_host,
    remote_service_host,
    start_remote_capture,
)


def test_is_pattern() -> None:
    assert _is_pattern("/tmp/*.pcap")
    assert _is_pattern("/tmp/file?.pcapng")
    assert not _is_pattern("/tmp/file.pcapng")


def test_escape_remote() -> None:
    assert _escape_remote("/tmp/with space/file.pcap") == "/tmp/with\\ space/file.pcap"


def test_latest_patterns() -> None:
    assert _latest_patterns("/tmp/") == ["/tmp/*.pcap*", "/tmp/*.cap*"]
    assert _latest_patterns("/tmp/*.pcap") == ["/tmp/*.pcap"]
    assert _latest_patterns("/tmp/file.pcapng") == []


def test_pull_remote_capture_missing_tools(monkeypatch) -> None:
    def fake_which(_name: str):
        return None

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", fake_which)
    from wifi_pipeline import remote

    result = remote.pull_remote_capture({"remote_host": "x", "remote_path": "/tmp/x.pcap"})
    assert result is None


def test_pull_remote_capture_scps(monkeypatch, tmp_path) -> None:
    checksum = hashlib.sha256(b"pcap").hexdigest()

    def fake_which(_name: str):
        return "C:\\Windows\\System32\\fake.exe"

    def fake_run(cmd, capture_output=None, text=None, check=False, **_kwargs):
        if cmd[0] == "ssh":
            remote_cmd = cmd[-1]
            if "ls -t" in remote_cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="/tmp/test.pcapng\n", stderr="")
            if "FILE=" in remote_cmd:
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout=(
                        "file_exists=yes\n"
                        "complete_marker=yes\n"
                        "checksum_file=yes\n"
                        f"checksum_value={checksum}\n"
                        "remote_size_bytes=4\n"
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")
        if cmd[0] == "scp":
            dest = cmd[-1]
            tmp_path.joinpath(dest).parent.mkdir(parents=True, exist_ok=True)
            tmp_path.joinpath(dest).write_bytes(b"pcap")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", fake_which)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)
    from wifi_pipeline import remote

    config = {"remote_host": "test@host", "remote_path": "/tmp/", "remote_dest_dir": str(tmp_path)}
    result = remote.pull_remote_capture(config, latest_only=True)
    assert result is not None
    assert result.exists()


def test_pull_remote_capture_rejects_checksum_mismatch(monkeypatch, tmp_path) -> None:
    def fake_which(_name: str):
        return "C:\\Windows\\System32\\fake.exe"

    def fake_run(cmd, capture_output=None, text=None, check=False, **_kwargs):
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=(
                    "file_exists=yes\n"
                    "complete_marker=yes\n"
                    "checksum_file=yes\n"
                    "checksum_value=deadbeef\n"
                    "remote_size_bytes=4\n"
                ),
                stderr="",
            )
        if cmd[0] == "scp":
            dest = Path(cmd[-1])
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"pcap")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", fake_which)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)
    from wifi_pipeline import remote

    result = remote.pull_remote_capture(
        {"remote_host": "test@host", "remote_path": "/tmp/test.pcapng", "remote_dest_dir": str(tmp_path)},
        latest_only=False,
    )

    assert result is None
    assert not (tmp_path / "test.pcapng").exists()


def test_ensure_public_key_generates_missing_key(monkeypatch, tmp_path) -> None:
    private_key = tmp_path / "id_ed25519"

    def fake_run(cmd, capture_output=None, text=None, check=False, **_kwargs):
        private_key.write_text("private", encoding="utf-8")
        Path(str(private_key) + ".pub").write_text("ssh-ed25519 AAAA test@example", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "ssh-keygen" if name == "ssh-keygen" else None)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = _ensure_public_key(str(private_key), generate_if_missing=True)

    assert result == Path(str(private_key) + ".pub")
    assert result.exists()


def test_pair_remote_host_installs_and_verifies_key(monkeypatch, tmp_path) -> None:
    public_key = tmp_path / "id_ed25519.pub"
    public_key.write_text("ssh-ed25519 AAAA test@example", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(cmd, capture_output=None, text=None, check=False, **_kwargs):
        commands.append(cmd)
        if cmd[-2:] == ["--", "printf", "paired"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="paired", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "ssh" if name == "ssh" else None)
    monkeypatch.setattr("wifi_pipeline.remote._ensure_public_key", lambda identity=None, generate_if_missing=True: public_key)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = pair_remote_host({"remote_host": "pi@raspberrypi"}, create_key=False)

    assert result is True
    assert commands[0][0] == "ssh"
    assert "authorized_keys" in commands[0][-1]


def test_bootstrap_remote_script_contains_capture_helper() -> None:
    script = _bootstrap_remote_script("/home/pi/wifi-pipeline", "/home/pi/wifi-pipeline/captures")

    assert "wifi-pipeline-capture" in script
    assert "wifi-pipeline-service" in script
    assert "wifi-pipeline-agent" in script
    assert "wifi-pipeline-capture-privileged" in script
    assert "complete_marker" in script
    assert "checksum_file" in script
    assert "/etc/sudoers.d/wifi-pipeline-capture" in script
    assert "CAPTURE_DIR=/home/pi/wifi-pipeline/captures" in script
    assert "apt-get install -y tcpdump" in script


def test_privileged_runner_script_hardens_output_path() -> None:
    script = _privileged_capture_runner_script("/home/pi/wifi-pipeline/captures")

    assert 'CAPTURE_DIR="/home/pi/wifi-pipeline/captures"' not in script
    assert "CAPTURE_DIR=/home/pi/wifi-pipeline/captures" in script
    assert 'CAPTURE_DIR_REAL="$(cd "$CAPTURE_DIR" && pwd -P)"' in script
    assert 'OUTPUT_REAL="$(cd "$OUTPUT_PARENT" && pwd -P)/$(basename "$OUTPUT")"' in script
    assert 'output path must stay under $CAPTURE_DIR_REAL' in script


def test_capture_agent_script_exposes_service_and_doctor_commands() -> None:
    script = _capture_agent_script("/home/pi/wifi-pipeline", "/home/pi/wifi-pipeline/captures")

    assert "#!/usr/bin/env bash" in script
    assert 'PROTOCOL="capture-agent/v1"' in script
    assert 'run_service()' in script
    assert 'run_doctor()' in script
    assert 'run_artifact_info()' in script


def test_resolve_remote_install_mode_prefers_bundle_when_available() -> None:
    assert _resolve_remote_install_mode("auto", prefer_bundle=True) == "bundle"
    assert _resolve_remote_install_mode("auto", prefer_bundle=False) == "native"
    assert _resolve_remote_install_mode("bundle", prefer_bundle=False) == "bundle"


def test_resolve_remote_install_profile_defaults_to_appliance() -> None:
    assert _resolve_remote_install_profile(None) == "appliance"
    assert _resolve_remote_install_profile("standard") == "standard"
    assert _resolve_remote_install_profile("bogus") == "appliance"


def test_discover_remote_appliances_uses_health_endpoint(monkeypatch) -> None:
    monkeypatch.setattr("wifi_pipeline.remote._candidate_discovery_hosts", lambda *args, **kwargs: ["192.168.1.10", "192.168.1.20"])
    monkeypatch.setattr(
        "wifi_pipeline.remote._probe_remote_appliance",
        lambda host, **kwargs: {
            "host": host,
            "ssh_target": f"pi@{host}",
            "health_endpoint": f"http://{host}:8741/health",
            "device_name": f"node-{host.rsplit('.', 1)[-1]}",
            "install_profile": "appliance",
            "health_port": "8741",
            "health_path": "/health",
            "control_mode": "agent",
            "agent_protocol": "capture-agent/v1",
            "capture_dir": "/home/pi/wifi-pipeline/captures",
            "service_status": "idle",
            "ssh_user": "pi",
        } if host.endswith(".10") else None,
    )

    results = discover_remote_appliances({}, max_hosts=8)

    assert len(results) == 1
    assert results[0]["ssh_target"] == "pi@192.168.1.10"


def test_appliance_profile_script_installs_health_endpoint() -> None:
    script = _appliance_profile_script("/home/pi/wifi-pipeline", "/home/pi/wifi-pipeline/captures", health_port=9001)

    assert "wifi-pipeline-health-http" in script
    assert "wifi-pipeline-health.socket" in script
    assert "wifi-pipeline-appliance.service" in script
    assert "HEALTH_PORT=9001" in script
    assert "ListenStream=$HEALTH_PORT" in script


def test_bootstrap_remote_host_prepares_remote_helper(monkeypatch) -> None:
    seen_inputs: list[str] = []

    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if input:
            seen_inputs.append(input)
        if cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=(
                "remote_root=/home/pi/wifi-pipeline\n"
                "capture_dir=/home/pi/wifi-pipeline/captures\n"
                "state_dir=/home/pi/wifi-pipeline/state\n"
                "capture_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-capture\n"
                "service_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-service\n"
                "agent_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-agent\n"
                "privilege_mode=sudoers_runner\n"
                "privileged_runner=/usr/local/bin/wifi-pipeline-capture-privileged\n"
            ),
            stderr="",
        )

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "ssh" if name == "ssh" else None)
    monkeypatch.setattr("wifi_pipeline.remote.pair_remote_host", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        "wifi_pipeline.remote._install_remote_appliance_profile",
        lambda *args, **kwargs: {
            "install_profile": "appliance",
            "health_port": "8741",
            "health_endpoint": "http://0.0.0.0:8741/health",
        },
    )
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = bootstrap_remote_host({"remote_host": "pi@raspberrypi"}, pair=True)

    assert result is not None
    assert result["capture_dir"] == "/home/pi/wifi-pipeline/captures"
    assert result["state_dir"] == "/home/pi/wifi-pipeline/state"
    assert result["service_cmd"] == "/home/pi/wifi-pipeline/bin/wifi-pipeline-service"
    assert result["agent_cmd"] == "/home/pi/wifi-pipeline/bin/wifi-pipeline-agent"
    assert result["install_profile"] == "appliance"
    assert result["health_port"] == "8741"
    assert result["health_endpoint"] == "http://0.0.0.0:8741/health"
    assert result["privilege_mode"] == "sudoers_runner"
    assert result["privileged_runner"] == "/usr/local/bin/wifi-pipeline-capture-privileged"
    assert seen_inputs
    assert "wifi-pipeline-capture" in seen_inputs[0]
    assert "wifi-pipeline-agent" in seen_inputs[0]


def test_bootstrap_remote_host_bundle_mode_uploads_bundle(monkeypatch, tmp_path) -> None:
    uploaded: list[list[str]] = []
    seen_inputs: list[str] = []
    bundle_path = tmp_path / "wifi-pipeline-agent-3.0.0-bundle.tar.gz"
    bundle_path.write_bytes(b"bundle")

    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if input:
            seen_inputs.append(input)
        if cmd[0] == "scp":
            uploaded.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh" and "tar -xzf" in cmd[-1]:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=(
                "remote_root=/home/pi/wifi-pipeline\n"
                "capture_dir=/home/pi/wifi-pipeline/captures\n"
                "state_dir=/home/pi/wifi-pipeline/state\n"
                "agent_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-agent\n"
                "capture_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-capture\n"
                "service_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-service\n"
                "privilege_mode=sudoers_runner\n"
                "privileged_runner=/usr/local/bin/wifi-pipeline-capture-privileged\n"
            ),
            stderr="",
        )

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "tool" if name in ("ssh", "scp") else None)
    monkeypatch.setattr("wifi_pipeline.remote.pair_remote_host", lambda *args, **kwargs: True)
    monkeypatch.setattr("wifi_pipeline.remote.build_capture_agent_bundle", lambda **kwargs: bundle_path)
    monkeypatch.setattr(
        "wifi_pipeline.remote._install_remote_appliance_profile",
        lambda *args, **kwargs: {
            "install_profile": "appliance",
            "health_port": "8741",
            "health_endpoint": "http://0.0.0.0:8741/health",
        },
    )
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = bootstrap_remote_host({"remote_host": "pi@raspberrypi"}, pair=True, install_mode="bundle")

    assert result is not None
    assert result["install_mode"] == "bundle"
    assert result["install_profile"] == "appliance"
    assert uploaded
    assert uploaded[0][0] == "scp"
    assert seen_inputs


def test_extract_capture_path_uses_last_nonempty_line() -> None:
    output = "[*] Saving capture to /tmp/capture.pcap\n/tmp/capture.pcap\n"

    assert _extract_capture_path(output) == "/tmp/capture.pcap"


def test_parse_key_value_output() -> None:
    parsed = _parse_key_value_output("one=1\ntwo=hello world\nignored\n")

    assert parsed == {"one": "1", "two": "hello world"}


def test_start_remote_capture_runs_helper_and_pulls_file(monkeypatch, tmp_path) -> None:
    commands: list[list[str]] = []
    checksum = hashlib.sha256(b"pcap").hexdigest()

    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        commands.append(cmd)
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            remote_cmd = cmd[-1]
            if "wifi-pipeline-agent" in remote_cmd and " service start " in remote_cmd:
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout='{"data":{"output":"/home/pi/wifi-pipeline/captures/capture_20260406_120000.pcap","pid":"1234","service_status":"running"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                    stderr="",
                )
            if "wifi-pipeline-agent" in remote_cmd and " service status" in remote_cmd:
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout='{"data":{"checksum_file":"/home/pi/wifi-pipeline/captures/capture_20260406_120000.pcap.sha256","complete_marker":"/home/pi/wifi-pipeline/captures/capture_20260406_120000.pcap.complete","last_capture":"/home/pi/wifi-pipeline/captures/capture_20260406_120000.pcap","last_exit_code":"0","last_result":"complete","log_file":"/home/pi/wifi-pipeline/state/capture-service.log","service_status":"idle"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                    stderr="",
                )
            if "wifi-pipeline-agent" in remote_cmd and " artifact-info " in remote_cmd:
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout=(
                        '{"data":{"checksum_file":"yes","checksum_value":"'
                        + checksum
                        + '","complete_marker":"yes","file_exists":"yes","remote_size_bytes":"4"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n'
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")
        if cmd[0] == "scp":
            destination = Path(cmd[-1])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"pcap")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda _name: "tool")
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = start_remote_capture(
        {"remote_host": "pi@raspberrypi", "remote_dest_dir": str(tmp_path)},
        interface="wlan0",
        duration=30,
    )

    assert result is not None
    assert result.exists()
    assert any("wifi-pipeline-agent" in " ".join(cmd) for cmd in commands if cmd[0] == "ssh")


def test_start_remote_capture_reports_privilege_gap(monkeypatch) -> None:
    statuses = iter(
        [
            subprocess.CompletedProcess(
                ["ssh"],
                0,
                stdout='{"data":{"output":"/home/pi/wifi-pipeline/captures/capture_20260406_120000.pcap","pid":"1234","service_status":"running"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            ),
            subprocess.CompletedProcess(
                ["ssh"],
                0,
                stdout='{"data":{"last_exit_code":"3","last_result":"failed","log_file":"/home/pi/wifi-pipeline/state/capture-service.log","service_status":"failed"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            ),
        ]
    )

    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            return next(statuses)
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda _name: "tool")
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = start_remote_capture({"remote_host": "pi@raspberrypi"}, interface="wlan0", duration=30)

    assert result is None


def test_doctor_remote_host_reports_success(monkeypatch) -> None:
    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout='{"data":{"agent":"yes","agent_path":"/home/pi/wifi-pipeline/bin/wifi-pipeline-agent","agent_protocol":"capture-agent/v1","appliance_service":"wifi-pipeline-appliance.service","appliance_service_active":"yes","appliance_service_enabled":"yes","capture_dir":"/home/pi/wifi-pipeline/captures","capture_dir_exists":"yes","capture_dir_writable":"yes","checksum_file":"yes","checksum_value":"abcd","complete_marker":"yes","control_mode":"agent","health_endpoint":"http://0.0.0.0:8741/health","health_path":"/health","health_port":"8741","health_service":"wifi-pipeline-health.service","health_socket":"wifi-pipeline-health.socket","health_socket_active":"yes","health_socket_enabled":"yes","helper":"yes","helper_path":"/home/pi/.local/bin/wifi-pipeline-capture","install_profile":"appliance","interface_exists":"yes","privilege_mode":"sudoers_runner","privileged_runner":"yes","privileged_runner_path":"/usr/local/bin/wifi-pipeline-capture-privileged","remote_size_bytes":"4","service":"yes","service_path":"/home/pi/.local/bin/wifi-pipeline-service","service_status":"idle","state_dir":"/home/pi/wifi-pipeline/state","state_dir_exists":"yes","state_dir_writable":"yes","tcpdump":"yes"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            )
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("wifi_pipeline.remote._ensure_public_key", lambda identity=None, generate_if_missing=False: Path("/tmp/id_ed25519.pub"))
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    report = doctor_remote_host(
        {"remote_host": "pi@raspberrypi", "remote_interface": "wlan0"},
        interface="wlan0",
    )

    assert report["ok"] is True
    assert report["remote"]["agent"] is True
    assert report["remote"]["helper"] is True
    assert report["remote"]["service"] is True
    assert report["remote"]["service_status"] == "idle"
    assert report["remote"]["install_profile"] == "appliance"
    assert report["remote"]["health_endpoint"] == "http://0.0.0.0:8741/health"
    assert report["remote"]["health_socket_enabled"] is True
    assert report["remote"]["appliance_service_enabled"] is True
    assert report["remote"]["state_dir_exists"] is True
    assert report["remote"]["checksum_file"] is True
    assert report["remote"]["privileged_runner"] is True
    assert report["remote"]["privilege_mode"] == "sudoers_runner"
    assert report["remote"]["control_mode"] == "agent"
    assert report["remote"]["capture_dir_writable"] is True
    assert report["remote"]["interface_exists"] is True


def test_doctor_remote_host_reports_missing_helper(monkeypatch) -> None:
    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            if "wifi-pipeline-agent" in cmd[-1]:
                return subprocess.CompletedProcess(cmd, 127, stdout="", stderr="not found")
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=(
                    "tcpdump=yes\n"
                    "helper=no\n"
                    "helper_path=/home/pi/wifi-pipeline/bin/wifi-pipeline-capture\n"
                    "service=no\n"
                    "service_path=/home/pi/wifi-pipeline/bin/wifi-pipeline-service\n"
                    "service_status=missing\n"
                    "state_dir=/home/pi/wifi-pipeline/state\n"
                    "state_dir_exists=yes\n"
                    "state_dir_writable=yes\n"
                    "privileged_runner=no\n"
                    "privileged_runner_path=/usr/local/bin/wifi-pipeline-capture-privileged\n"
                    "privilege_mode=fallback\n"
                    "capture_dir=/home/pi/wifi-pipeline/captures\n"
                    "capture_dir_exists=yes\n"
                    "capture_dir_writable=yes\n"
                ),
                stderr="",
            )
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("wifi_pipeline.remote._ensure_public_key", lambda identity=None, generate_if_missing=False: None)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    report = doctor_remote_host({"remote_host": "pi@raspberrypi"})

    assert report["ok"] is False
    assert report["local"]["public_key"] is False
    assert report["remote"]["agent"] is False
    assert report["remote"]["helper"] is False
    assert report["remote"]["service"] is False
    assert report["remote"]["control_mode"] == "legacy_shell"
    assert report["remote"]["privilege_mode"] == "fallback"


def test_remote_service_host_reports_last_capture(monkeypatch) -> None:
    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout='{"data":{"last_capture":"/home/pi/wifi-pipeline/captures/capture_latest.pcap","last_result":"complete","service_status":"idle"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            )
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "ssh" if name == "ssh" else None)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = remote_service_host({"remote_host": "pi@raspberrypi"}, "last-capture")

    assert result is not None
    assert result["last_capture"] == "/home/pi/wifi-pipeline/captures/capture_latest.pcap"
