from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .ui import done, err, info, ok, section, warn


@dataclass
class RemoteSource:
    host: str
    path: str
    port: int
    identity: str
    dest_dir: Path
    poll_interval: int


def _has_ssh_tools() -> bool:
    return bool(shutil.which("ssh")) and bool(shutil.which("scp"))


def _is_pattern(path: str) -> bool:
    return any(char in path for char in ("*", "?", "[", "]"))


def _escape_remote(pattern: str) -> str:
    return pattern.replace(" ", "\\ ")


def _latest_patterns(path: str) -> List[str]:
    if path.endswith("/"):
        base = path.rstrip("/")
        return [f"{base}/*.pcap*", f"{base}/*.cap*"]
    if _is_pattern(path):
        return [path]
    return []


def _ssh_args(source: RemoteSource) -> List[str]:
    args = ["ssh"]
    if source.port:
        args.extend(["-p", str(source.port)])
    if source.identity:
        args.extend(["-i", source.identity])
    args.append(source.host)
    return args


def _scp_args(source: RemoteSource) -> List[str]:
    args = ["scp"]
    if source.port:
        args.extend(["-P", str(source.port)])
    if source.identity:
        args.extend(["-i", source.identity])
    return args


def _resolve_latest_remote_path(source: RemoteSource) -> Optional[str]:
    patterns = _latest_patterns(source.path)
    if not patterns:
        return None
    escaped = " ".join(_escape_remote(pattern) for pattern in patterns)
    cmd = _ssh_args(source) + ["--", "sh", "-lc", f"ls -t {escaped} 2>/dev/null | head -n 1"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None
    latest = (result.stdout or "").strip()
    return latest or None


def _source_from_config(
    config: Dict[str, object],
    host: Optional[str] = None,
    path: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    dest_dir: Optional[str] = None,
    poll_interval: Optional[int] = None,
) -> RemoteSource:
    return RemoteSource(
        host=str(host or config.get("remote_host") or "").strip(),
        path=str(path or config.get("remote_path") or "").strip(),
        port=int(port or config.get("remote_port", 22) or 22),
        identity=str(identity or config.get("remote_identity") or "").strip(),
        dest_dir=Path(str(dest_dir or config.get("remote_dest_dir") or "./pipeline_output/remote_imports")).resolve(),
        poll_interval=int(poll_interval or config.get("remote_poll_interval", 8) or 8),
    )


def pull_remote_capture(
    config: Dict[str, object],
    host: Optional[str] = None,
    path: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    dest_dir: Optional[str] = None,
    latest_only: bool = True,
) -> Optional[Path]:
    section("Remote Capture Pull")

    if not _has_ssh_tools():
        err("ssh/scp not found on PATH. Install OpenSSH client and re-run.")
        return None

    source = _source_from_config(
        config, host=host, path=path, port=port, identity=identity, dest_dir=dest_dir
    )
    if not source.host or not source.path:
        err("Remote host and path are required. Use --host and --path or set them in config.")
        return None

    remote_path = source.path
    if latest_only and (_is_pattern(remote_path) or remote_path.endswith("/")):
        resolved = _resolve_latest_remote_path(source)
        if not resolved:
            err("Could not resolve a remote capture file. Check the path or pattern.")
            return None
        remote_path = resolved

    source.dest_dir.mkdir(parents=True, exist_ok=True)
    filename = os.path.basename(remote_path.rstrip("/")) or "remote_capture.pcapng"
    local_path = source.dest_dir / filename

    cmd = _scp_args(source) + [f"{source.host}:{remote_path}", str(local_path)]
    info(f"Pulling {remote_path} from {source.host}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        err(result.stderr.strip() or result.stdout.strip() or "scp failed")
        return None

    ok(f"Saved remote capture to {local_path}")
    return local_path


def watch_remote_capture(
    config: Dict[str, object],
    host: Optional[str] = None,
    path: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    dest_dir: Optional[str] = None,
    interval: Optional[int] = None,
    latest_only: bool = True,
) -> None:
    source = _source_from_config(
        config, host=host, path=path, port=port, identity=identity, dest_dir=dest_dir, poll_interval=interval
    )
    poll = max(2, int(source.poll_interval))
    info(f"Watching {source.host}:{source.path} every {poll}s (Ctrl-C to stop).")
    try:
        while True:
            pull_remote_capture(
                config,
                host=source.host,
                path=source.path,
                port=source.port,
                identity=source.identity,
                dest_dir=str(source.dest_dir),
                latest_only=latest_only,
            )
            time.sleep(poll)
    except KeyboardInterrupt:
        done("Remote watch stopped.")
