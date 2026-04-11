from __future__ import annotations

import base64
import calendar
import copy
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SECURE_MESH_PROTOCOL = "wifi-pipeline-secure/v1"
SECURE_MESH_REGISTRY_SCHEMA = 1
DEFAULT_SECURE_MESH_REGISTRY = "./pipeline_output/secure_mesh/devices.json"
DEFAULT_SECURE_MESH_PRIVATE_DIR = "~/.wifi-pipeline/secure_mesh"
DEFAULT_SECURE_MESH_REPLAY_CACHE = "./pipeline_output/secure_mesh/replay_cache.json"

DEVICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
PAIRING_BUNDLE_TYPE = "secure_mesh_pairing_public_v1"
WIREGUARD_IDENTITY_TYPE = "secure_mesh_wireguard_identity_v1"
COMMAND_ENVELOPE_TYPE = "secure_mesh_command_envelope_v1"
COMMAND_BUNDLE_TYPE = "secure_mesh_command_bundle_v1"
APPROVED_BODY_TYPE = "secure_mesh_approved_body_v1"
DEFAULT_WIREGUARD_LISTEN_PORT = 51820
PAIRING_TOKEN_BYTES = 24
APPROVAL_CODE_BYTES = 16
DEFAULT_APPROVAL_TTL_SECONDS = 300
COMMAND_NONCE_BYTES = 12
TRANSPORT_PRIORITIES = {
    "wireguard": 10,
    "secure_http": 20,
    "ssh": 30,
    "ethernet": 40,
    "serial": 50,
    "http_health": 60,
    "hotspot": 70,
    "bluetooth": 80,
    "radio": 90,
}
TRANSPORT_HINT_ALIASES = {
    "ssh": "ssh",
    "ssh_target": "ssh",
    "wireguard": "wireguard",
    "wireguard_endpoint": "wireguard",
    "tunnel_ip": "wireguard",
    "http_health": "http_health",
    "health": "http_health",
    "health_endpoint": "http_health",
    "hotspot": "hotspot",
    "hotspot_ssid": "hotspot",
    "bluetooth": "bluetooth",
    "bluetooth_id": "bluetooth",
    "serial": "serial",
    "serial_path": "serial",
    "ethernet": "ethernet",
    "ethernet_host": "ethernet",
    "radio": "radio",
}
DISCOVERY_HINT_TRANSPORT_FIELDS = {
    "ssh_target": ("ssh", "SSH target advertised by discovery."),
    "host": ("ethernet", "Host/IP advertised by discovery."),
    "health_endpoint": ("http_health", "Public health endpoint. Hint only, not a trust boundary."),
    "wireguard_endpoint": ("wireguard", "WireGuard endpoint hint advertised by discovery."),
    "wireguard": ("wireguard", "WireGuard tunnel hint advertised by discovery."),
    "tunnel_ip": ("wireguard", "WireGuard tunnel IP hint advertised by discovery."),
    "hotspot_ssid": ("hotspot", "Hotspot SSID hint. Transport only, never identity."),
    "hotspot": ("hotspot", "Hotspot hint. Transport only, never identity."),
    "bluetooth_id": ("bluetooth", "Bluetooth device hint. Transport only, never identity."),
    "bluetooth": ("bluetooth", "Bluetooth hint. Transport only, never identity."),
    "serial_path": ("serial", "Serial path hint. Transport only, never identity."),
    "serial": ("serial", "Serial hint. Transport only, never identity."),
    "ethernet_host": ("ethernet", "Ethernet host/IP hint. Transport only, never identity."),
    "ethernet": ("ethernet", "Ethernet hint. Transport only, never identity."),
    "radio": ("radio", "Radio link hint. Transport only, never identity."),
}
DISCOVERY_IDENTITY_HINT_KEYS = (
    "secure_mesh_fingerprint",
    "mesh_fingerprint",
    "fingerprint",
    "secure_mesh_device_id",
    "mesh_device_id",
    "device_id",
    "device_name",
)
SENSITIVE_FIELD_MARKERS = (
    "private_key",
    "secret",
    "psk",
    "pairing_token",
    "token",
    "seed",
    "mnemonic",
)

ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "controller": [
        "doctor.run",
        "service.status",
        "service.start",
        "service.stop",
        "service.last_capture",
        "capture.start",
        "capture.stop",
        "capture.pull",
        "artifact.verify",
        "config.update",
        "mesh.rotate_key",
        "mesh.revoke",
    ],
    "capture_appliance": [
        "doctor.reply",
        "service.status.reply",
        "capture.status.reply",
        "capture.artifact.send",
        "artifact.verify.reply",
    ],
    "analyzer": [
        "artifact.receive",
        "artifact.verify",
        "analysis.run",
        "analysis.reply",
    ],
    "observer": [
        "doctor.run",
        "service.status",
    ],
}
DEFAULT_SENSITIVE_MESH_ACTIONS = [
    "capture.start",
    "capture.stop",
    "service.start",
    "service.stop",
    "config.update",
    "mesh.rotate_key",
    "mesh.revoke",
]


def utc_stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def default_registry_path(config: Optional[Dict[str, object]] = None) -> Path:
    value = str((config or {}).get("secure_mesh_registry_path") or DEFAULT_SECURE_MESH_REGISTRY)
    return Path(value).expanduser().resolve()


def default_private_dir(config: Optional[Dict[str, object]] = None) -> Path:
    value = str((config or {}).get("secure_mesh_private_dir") or DEFAULT_SECURE_MESH_PRIVATE_DIR)
    return Path(value).expanduser().resolve()


def default_replay_cache_path(config: Optional[Dict[str, object]] = None) -> Path:
    value = str((config or {}).get("secure_mesh_replay_cache_path") or DEFAULT_SECURE_MESH_REPLAY_CACHE)
    return Path(value).expanduser().resolve()


def identity_path(
    config: Optional[Dict[str, object]] = None,
    *,
    device_id: str,
    private_dir: Optional[Path] = None,
) -> Path:
    safe_device_id = re.sub(r"[^A-Za-z0-9_.-]", "_", normalize_device_id(device_id))
    selected_dir = Path(private_dir).expanduser().resolve() if private_dir else default_private_dir(config)
    return selected_dir / f"device_{safe_device_id}.json"


def wireguard_identity_path(
    config: Optional[Dict[str, object]] = None,
    *,
    device_id: str,
    private_dir: Optional[Path] = None,
) -> Path:
    safe_device_id = re.sub(r"[^A-Za-z0-9_.-]", "_", normalize_device_id(device_id))
    selected_dir = Path(private_dir).expanduser().resolve() if private_dir else default_private_dir(config)
    return selected_dir / f"wireguard_{safe_device_id}.json"


def role_permissions(role: str) -> List[str]:
    return list(ROLE_PERMISSIONS.get(str(role or "").strip(), []))


def is_sensitive_field(name: object) -> bool:
    key = str(name or "").strip().lower()
    return any(marker in key for marker in SENSITIVE_FIELD_MARKERS)


def redact_mesh_secrets(payload: Dict[str, object]) -> Dict[str, object]:
    sanitized = copy.deepcopy(dict(payload))
    for key in list(sanitized.keys()):
        if str(key).lower().startswith("secure_mesh_") and is_sensitive_field(key):
            sanitized[key] = ""
    return sanitized


def redact_public_payload(payload: object) -> object:
    if isinstance(payload, dict):
        return {
            str(key): "[redacted]" if is_sensitive_field(key) else redact_public_payload(value)
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [redact_public_payload(item) for item in payload]
    return payload


def _assert_no_private_material(payload: object, path: str = "") -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            current_path = f"{path}.{key}" if path else str(key)
            if is_sensitive_field(key):
                raise ValueError(f"secure mesh public registry cannot contain secret field: {current_path}")
            _assert_no_private_material(value, current_path)
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            _assert_no_private_material(item, f"{path}[{index}]")


def normalize_device_id(device_id: str) -> str:
    value = str(device_id or "").strip()
    if not DEVICE_ID_PATTERN.fullmatch(value):
        raise ValueError("device_id must be 1-64 chars using letters, numbers, dot, underscore, dash, or colon")
    return value


def _clean_public_key(value: object) -> str:
    return str(value or "").strip()


def fingerprint_for_public_material(*parts: object) -> str:
    material = "\n".join(str(part or "").strip() for part in parts if str(part or "").strip()).encode("utf-8")
    if not material:
        raise ValueError("public key material is required to compute a fingerprint")
    digest = hashlib.blake2b(material, digest_size=15, person=b"wifi-mesh-v1").digest()
    text = base64.b32encode(digest).decode("ascii").rstrip("=")
    return "-".join(text[index : index + 4] for index in range(0, len(text), 4))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: object) -> bytes:
    value = str(text or "").strip()
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _public_key_text(kind: str, raw: bytes) -> str:
    return f"{kind}:{_b64url(raw)}"


def _parse_public_key_text(value: object, expected_kind: str) -> bytes:
    text = str(value or "").strip()
    prefix = f"{expected_kind}:"
    if not text.startswith(prefix):
        raise ValueError(f"expected {expected_kind} public key text")
    raw = _b64url_decode(text[len(prefix) :])
    if len(raw) != 32:
        raise ValueError(f"{expected_kind} public key must be 32 bytes")
    return raw


def _canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _json_or_text(data: bytes) -> object:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return _b64url(data)


def _body_to_bytes(body: object) -> bytes:
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return _canonical_json_bytes(body)


def _utc_after(seconds: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + max(1, int(seconds))))


def _utc_to_epoch(value: object) -> float:
    text = str(value or "").strip()
    if not text:
        raise ValueError("UTC timestamp is required")
    try:
        return float(calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ")))
    except ValueError as exc:
        raise ValueError(f"invalid UTC timestamp: {text}") from exc


def _private_pem_text(private_key: object) -> str:
    return (
        private_key.private_bytes(  # type: ignore[attr-defined]
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode("ascii")
        .strip()
    )


def _ed25519_public_text(private_key: ed25519.Ed25519PrivateKey) -> str:
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _public_key_text("ed25519", public)


def _x25519_public_text(private_key: x25519.X25519PrivateKey) -> str:
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _public_key_text("x25519", public)


def _load_ed25519_private(pem: str) -> ed25519.Ed25519PrivateKey:
    key = serialization.load_pem_private_key(str(pem or "").encode("ascii"), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("identity private key is not Ed25519")
    return key


def _load_x25519_private(pem: str) -> x25519.X25519PrivateKey:
    key = serialization.load_pem_private_key(str(pem or "").encode("ascii"), password=None)
    if not isinstance(key, x25519.X25519PrivateKey):
        raise ValueError("encryption private key is not X25519")
    return key


def _load_ed25519_public(text: str) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(_parse_public_key_text(text, "ed25519"))


def _load_x25519_public(text: str) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(_parse_public_key_text(text, "x25519"))


def _wireguard_keypair() -> tuple[str, str]:
    private_key = x25519.X25519PrivateKey.generate()
    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
    )


def _wireguard_allowed_ip(address: str) -> str:
    value = str(address or "").strip()
    if not value:
        return ""
    try:
        interface = ipaddress.ip_interface(value)
        prefix = 32 if interface.version == 4 else 128
        return f"{interface.ip}/{prefix}"
    except ValueError:
        if "/" in value:
            return value
        try:
            address_obj = ipaddress.ip_address(value)
            prefix = 32 if address_obj.version == 4 else 128
            return f"{address_obj}/{prefix}"
        except ValueError:
            return value


def generate_pairing_token(num_bytes: int = PAIRING_TOKEN_BYTES) -> str:
    return _b64url(secrets.token_bytes(max(16, int(num_bytes))))


def generate_mesh_approval_code(num_bytes: int = APPROVAL_CODE_BYTES) -> str:
    return _b64url(secrets.token_bytes(max(12, int(num_bytes))))


def pairing_token_hash(token: str, *context: object) -> str:
    token_text = str(token or "").strip()
    if not token_text:
        raise ValueError("pairing token is required")
    material = "\n".join([token_text] + [str(item or "").strip() for item in context]).encode("utf-8")
    digest = hashlib.blake2b(material, digest_size=32, person=b"wifi-pair-v1").digest()
    return _b64url(digest)


def mesh_approval_hash(
    approval_code: str,
    *,
    sender_device_id: str,
    receiver_device_id: str,
    command: str,
    counter: int,
    message_id: str,
) -> str:
    code = str(approval_code or "").strip()
    if not code:
        raise ValueError("operator approval code is required")
    material = _canonical_json_bytes(
        {
            "protocol": SECURE_MESH_PROTOCOL,
            "purpose": "operator-approval",
            "sender_device_id": normalize_device_id(sender_device_id),
            "receiver_device_id": normalize_device_id(receiver_device_id),
            "command": str(command or "").strip(),
            "counter": int(counter),
            "message_id": str(message_id or "").strip(),
            "approval_code": code,
        }
    )
    return _b64url(hashlib.blake2b(material, digest_size=32, person=b"wifi-appr-v1").digest())


def sensitive_mesh_actions(config: Optional[Dict[str, object]] = None) -> List[str]:
    configured = (config or {}).get("secure_mesh_sensitive_actions")
    if configured in (None, ""):
        return list(DEFAULT_SENSITIVE_MESH_ACTIONS)
    if isinstance(configured, str):
        return [item.strip() for item in configured.split(",") if item.strip()]
    return sorted({str(item or "").strip() for item in list(configured or []) if str(item or "").strip()})


def is_sensitive_mesh_command(command: str, config: Optional[Dict[str, object]] = None) -> bool:
    return str(command or "").strip() in set(sensitive_mesh_actions(config))


def _normalize_actions(role: str, actions: Optional[Iterable[str]]) -> List[str]:
    allowed_for_role = set(role_permissions(role))
    if actions is None:
        return sorted(allowed_for_role)
    cleaned = sorted({str(action or "").strip() for action in actions if str(action or "").strip()})
    disallowed = [action for action in cleaned if action not in allowed_for_role]
    if disallowed:
        raise ValueError(
            f"role {role!r} cannot be granted action(s): {', '.join(disallowed)}"
        )
    return cleaned


def _transport_priority(transport_type: str) -> int:
    return TRANSPORT_PRIORITIES.get(str(transport_type or "").strip().lower(), 100)


def _normalize_transport_type(value: object) -> str:
    key = str(value or "").strip().lower()
    return TRANSPORT_HINT_ALIASES.get(key, key or "unknown")


def _host_without_user(value: object) -> str:
    text = str(value or "").strip()
    if "@" in text:
        return text.split("@", 1)[1].strip().lower()
    if text.startswith("http://") or text.startswith("https://"):
        text = text.split("://", 1)[1]
        text = text.split("/", 1)[0]
    return text.strip().lower()


@dataclass
class MeshCommandEnvelope:
    sender_device_id: str
    receiver_device_id: str
    command: str
    message_id: str
    counter: int
    created_at_utc: str
    expires_at_utc: str
    nonce: str
    ciphertext: str
    associated_data: str
    signature: str
    protocol: str = SECURE_MESH_PROTOCOL
    envelope_type: str = COMMAND_ENVELOPE_TYPE

    def __post_init__(self) -> None:
        self.sender_device_id = normalize_device_id(self.sender_device_id)
        self.receiver_device_id = normalize_device_id(self.receiver_device_id)
        self.command = str(self.command or "").strip()
        if not self.command:
            raise ValueError("command is required")
        self.message_id = str(self.message_id or "").strip()
        if not self.message_id:
            raise ValueError("message_id is required")
        self.counter = int(self.counter)
        if self.counter < 0:
            raise ValueError("counter must be non-negative")
        self.created_at_utc = str(self.created_at_utc or "").strip()
        self.expires_at_utc = str(self.expires_at_utc or "").strip()
        self.nonce = str(self.nonce or "").strip()
        self.ciphertext = str(self.ciphertext or "").strip()
        self.associated_data = str(self.associated_data or "").strip()
        self.signature = str(self.signature or "").strip()
        if str(self.protocol or "") != SECURE_MESH_PROTOCOL:
            raise ValueError("unsupported secure mesh command protocol")
        if str(self.envelope_type or "") != COMMAND_ENVELOPE_TYPE:
            raise ValueError("unsupported secure mesh command envelope type")

    @classmethod
    def from_dict(cls, payload: Dict[str, object]) -> "MeshCommandEnvelope":
        if not isinstance(payload, dict):
            raise ValueError("secure mesh command envelope must be a JSON object")
        return cls(
            protocol=str(payload.get("protocol") or SECURE_MESH_PROTOCOL),
            envelope_type=str(payload.get("envelope_type") or ""),
            sender_device_id=str(payload.get("sender_device_id") or ""),
            receiver_device_id=str(payload.get("receiver_device_id") or ""),
            command=str(payload.get("command") or ""),
            message_id=str(payload.get("message_id") or ""),
            counter=int(payload.get("counter", 0) or 0),
            created_at_utc=str(payload.get("created_at_utc") or ""),
            expires_at_utc=str(payload.get("expires_at_utc") or ""),
            nonce=str(payload.get("nonce") or ""),
            ciphertext=str(payload.get("ciphertext") or ""),
            associated_data=str(payload.get("associated_data") or ""),
            signature=str(payload.get("signature") or ""),
        )

    def metadata(self) -> Dict[str, object]:
        return {
            "protocol": self.protocol,
            "envelope_type": self.envelope_type,
            "sender_device_id": self.sender_device_id,
            "receiver_device_id": self.receiver_device_id,
            "command": self.command,
            "message_id": self.message_id,
            "counter": self.counter,
            "created_at_utc": self.created_at_utc,
            "expires_at_utc": self.expires_at_utc,
        }

    def signed_payload(self) -> Dict[str, object]:
        payload = self.metadata()
        payload.update(
            {
                "nonce": self.nonce,
                "ciphertext": self.ciphertext,
                "associated_data": self.associated_data,
            }
        )
        return payload

    def to_dict(self) -> Dict[str, object]:
        payload = self.signed_payload()
        payload["signature"] = self.signature
        return payload


@dataclass
class MeshReplayCache:
    path: Optional[Path] = None
    seen_message_ids: set[str] = field(default_factory=set)
    seen_nonces: set[str] = field(default_factory=set)
    highest_counters: Dict[str, int] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "MeshReplayCache":
        selected = Path(path).expanduser().resolve()
        if not selected.exists():
            return cls(path=selected)
        with open(selected, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError(f"secure mesh replay cache must be a JSON object: {selected}")
        return cls(
            path=selected,
            seen_message_ids={str(item) for item in list(payload.get("seen_message_ids") or [])},
            seen_nonces={str(item) for item in list(payload.get("seen_nonces") or [])},
            highest_counters={str(key): int(value) for key, value in dict(payload.get("highest_counters") or {}).items()},
        )

    def save(self) -> Optional[Path]:
        if not self.path:
            return None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": SECURE_MESH_REGISTRY_SCHEMA,
            "protocol": SECURE_MESH_PROTOCOL,
            "updated_at_utc": utc_stamp(),
            "seen_message_ids": sorted(self.seen_message_ids),
            "seen_nonces": sorted(self.seen_nonces),
            "highest_counters": dict(sorted(self.highest_counters.items())),
        }
        tmp_path = self.path.with_name(f"{self.path.name}.tmp")
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        tmp_path.replace(self.path)
        return self.path

    def check_and_record(self, envelope: MeshCommandEnvelope) -> None:
        if envelope.message_id in self.seen_message_ids:
            raise ValueError("replayed secure mesh message_id rejected")
        key = f"{envelope.sender_device_id}->{envelope.receiver_device_id}"
        highest = int(self.highest_counters.get(key, -1))
        if envelope.counter <= highest:
            raise ValueError("replayed secure mesh counter rejected")
        nonce_key = f"{key}:{envelope.command}:{envelope.nonce}"
        if nonce_key in self.seen_nonces:
            raise ValueError("replayed secure mesh nonce rejected")
        self.seen_message_ids.add(envelope.message_id)
        self.seen_nonces.add(nonce_key)
        self.highest_counters[key] = envelope.counter


@dataclass
class MeshTransportHint:
    transport_type: str
    target: str
    status: str = "detected"
    source: str = ""
    detail: str = ""
    priority: int = 100
    metadata: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.transport_type = _normalize_transport_type(self.transport_type)
        self.target = str(self.target or "").strip()
        self.status = str(self.status or "detected").strip()
        self.source = str(self.source or "").strip()
        self.detail = str(self.detail or "").strip()
        self.priority = int(self.priority if self.priority is not None else _transport_priority(self.transport_type))
        if self.priority == 100:
            self.priority = _transport_priority(self.transport_type)
        self.metadata = {str(key): str(value) for key, value in dict(self.metadata or {}).items()}

    def to_dict(self) -> Dict[str, object]:
        return {
            "type": self.transport_type,
            "target": self.target,
            "status": self.status,
            "source": self.source,
            "detail": self.detail,
            "priority": self.priority,
            "metadata": dict(self.metadata),
        }


@dataclass
class MeshDiscoveryRecord:
    source: str
    device_id_hint: str = ""
    fingerprint_hint: str = ""
    trusted: bool = False
    trust_status: str = "untrusted"
    trust_reason: str = "Discovery is only a hint until a paired fingerprint matches."
    matched_device_id: str = ""
    revoked: bool = False
    transports: List[MeshTransportHint] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.source = str(self.source or "").strip()
        self.device_id_hint = str(self.device_id_hint or "").strip()
        self.fingerprint_hint = str(self.fingerprint_hint or "").strip()
        self.trust_status = str(self.trust_status or ("trusted" if self.trusted else "untrusted")).strip()
        self.trust_reason = str(self.trust_reason or "").strip()
        self.matched_device_id = str(self.matched_device_id or "").strip()
        self.transports = sorted(
            list(self.transports or []),
            key=lambda item: (item.priority, item.transport_type, item.target),
        )
        self.metadata = {str(key): str(value) for key, value in dict(self.metadata or {}).items()}

    def best_transport(self) -> Optional[MeshTransportHint]:
        if not self.transports:
            return None
        trusted_bias = 0 if self.trusted and not self.revoked else 1000
        return sorted(
            self.transports,
            key=lambda item: (
                trusted_bias,
                0 if item.status in ("reachable", "configured", "detected") else 50,
                item.priority,
                item.transport_type,
            ),
        )[0]

    def to_dict(self) -> Dict[str, object]:
        best = self.best_transport()
        return {
            "source": self.source,
            "device_id_hint": self.device_id_hint,
            "fingerprint_hint": self.fingerprint_hint,
            "trusted": self.trusted,
            "trust_status": self.trust_status,
            "trust_reason": self.trust_reason,
            "matched_device_id": self.matched_device_id,
            "revoked": self.revoked,
            "best_transport": best.to_dict() if best else {},
            "transports": [item.to_dict() for item in self.transports],
            "metadata": dict(self.metadata),
        }


@dataclass
class MeshRoutePlan:
    device_id: str
    selected: bool = False
    transport: Optional[MeshTransportHint] = None
    discovery: Optional[MeshDiscoveryRecord] = None
    reason: str = ""
    require_trusted: bool = True
    allowed_transports: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.device_id = normalize_device_id(self.device_id)
        self.reason = str(self.reason or "").strip()
        self.allowed_transports = [_normalize_transport_type(item) for item in list(self.allowed_transports or [])]

    def to_dict(self) -> Dict[str, object]:
        return {
            "device_id": self.device_id,
            "selected": self.selected,
            "reason": self.reason,
            "require_trusted": self.require_trusted,
            "allowed_transports": list(self.allowed_transports),
            "transport": self.transport.to_dict() if self.transport else {},
            "discovery": self.discovery.to_dict() if self.discovery else {},
        }


@dataclass
class MeshDeviceRecord:
    device_id: str
    role: str
    public_identity_key: str
    public_encryption_key: str
    fingerprint: str
    allowed_actions: List[str] = field(default_factory=list)
    allowed_tunnel_ip: str = ""
    transport_hints: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, str] = field(default_factory=dict)
    created_at_utc: str = field(default_factory=utc_stamp)
    last_seen_at_utc: str = ""
    revoked: bool = False

    def __post_init__(self) -> None:
        self.device_id = normalize_device_id(self.device_id)
        self.role = str(self.role or "").strip()
        if self.role not in ROLE_PERMISSIONS:
            raise ValueError(f"unknown secure mesh role: {self.role!r}")
        self.public_identity_key = _clean_public_key(self.public_identity_key)
        self.public_encryption_key = _clean_public_key(self.public_encryption_key)
        if not self.public_identity_key:
            raise ValueError("public_identity_key is required")
        if not self.public_encryption_key:
            raise ValueError("public_encryption_key is required")
        expected_fingerprint = fingerprint_for_public_material(
            self.device_id,
            self.role,
            self.public_identity_key,
            self.public_encryption_key,
        )
        provided_fingerprint = str(self.fingerprint or "").strip()
        if provided_fingerprint and provided_fingerprint != expected_fingerprint:
            raise ValueError("secure mesh fingerprint does not match the public device material")
        self.fingerprint = expected_fingerprint
        self.allowed_actions = _normalize_actions(self.role, self.allowed_actions)
        self.allowed_tunnel_ip = str(self.allowed_tunnel_ip or "").strip()
        self.transport_hints = {str(k): str(v) for k, v in dict(self.transport_hints or {}).items()}
        self.metadata = {str(k): str(v) for k, v in dict(self.metadata or {}).items()}
        _assert_no_private_material(self.to_public_dict())

    @classmethod
    def create(
        cls,
        *,
        device_id: str,
        role: str,
        public_identity_key: str,
        public_encryption_key: str,
        allowed_actions: Optional[Iterable[str]] = None,
        allowed_tunnel_ip: str = "",
        transport_hints: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> "MeshDeviceRecord":
        fingerprint = fingerprint_for_public_material(device_id, role, public_identity_key, public_encryption_key)
        return cls(
            device_id=device_id,
            role=role,
            public_identity_key=public_identity_key,
            public_encryption_key=public_encryption_key,
            fingerprint=fingerprint,
            allowed_actions=_normalize_actions(role, allowed_actions),
            allowed_tunnel_ip=allowed_tunnel_ip,
            transport_hints=dict(transport_hints or {}),
            metadata=dict(metadata or {}),
        )

    @classmethod
    def from_dict(cls, payload: Dict[str, object]) -> "MeshDeviceRecord":
        _assert_no_private_material(payload)
        return cls(
            device_id=str(payload.get("device_id") or ""),
            role=str(payload.get("role") or ""),
            public_identity_key=str(payload.get("public_identity_key") or ""),
            public_encryption_key=str(payload.get("public_encryption_key") or ""),
            fingerprint=str(payload.get("fingerprint") or ""),
            allowed_actions=[str(action) for action in list(payload.get("allowed_actions") or [])],
            allowed_tunnel_ip=str(payload.get("allowed_tunnel_ip") or ""),
            transport_hints={str(k): str(v) for k, v in dict(payload.get("transport_hints") or {}).items()},
            metadata={str(k): str(v) for k, v in dict(payload.get("metadata") or {}).items()},
            created_at_utc=str(payload.get("created_at_utc") or utc_stamp()),
            last_seen_at_utc=str(payload.get("last_seen_at_utc") or ""),
            revoked=bool(payload.get("revoked", False)),
        )

    def to_public_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "device_id": self.device_id,
            "role": self.role,
            "public_identity_key": self.public_identity_key,
            "public_encryption_key": self.public_encryption_key,
            "fingerprint": self.fingerprint,
            "allowed_actions": list(self.allowed_actions),
            "allowed_tunnel_ip": self.allowed_tunnel_ip,
            "transport_hints": dict(self.transport_hints),
            "metadata": dict(self.metadata),
            "created_at_utc": self.created_at_utc,
            "last_seen_at_utc": self.last_seen_at_utc,
            "revoked": self.revoked,
        }
        _assert_no_private_material(payload)
        return payload

    def allows(self, action: str) -> bool:
        return not self.revoked and str(action or "").strip() in set(self.allowed_actions)

    def mark_seen(self, when_utc: Optional[str] = None) -> None:
        self.last_seen_at_utc = when_utc or utc_stamp()


@dataclass
class MeshLocalIdentity:
    device_id: str
    role: str
    public_identity_key: str
    public_encryption_key: str
    identity_private_key_pem: str
    encryption_private_key_pem: str
    fingerprint: str
    created_at_utc: str = field(default_factory=utc_stamp)

    def __post_init__(self) -> None:
        self.device_id = normalize_device_id(self.device_id)
        self.role = str(self.role or "").strip()
        if self.role not in ROLE_PERMISSIONS:
            raise ValueError(f"unknown secure mesh role: {self.role!r}")
        if not str(self.identity_private_key_pem or "").strip():
            raise ValueError("identity_private_key_pem is required")
        if not str(self.encryption_private_key_pem or "").strip():
            raise ValueError("encryption_private_key_pem is required")
        expected = fingerprint_for_public_material(
            self.device_id,
            self.role,
            self.public_identity_key,
            self.public_encryption_key,
        )
        if str(self.fingerprint or "").strip() and str(self.fingerprint).strip() != expected:
            raise ValueError("local identity fingerprint does not match public device material")
        self.fingerprint = expected

    @classmethod
    def generate(cls, *, device_id: str, role: str) -> "MeshLocalIdentity":
        identity_key = ed25519.Ed25519PrivateKey.generate()
        encryption_key = x25519.X25519PrivateKey.generate()
        public_identity_key = _ed25519_public_text(identity_key)
        public_encryption_key = _x25519_public_text(encryption_key)
        fingerprint = fingerprint_for_public_material(device_id, role, public_identity_key, public_encryption_key)
        return cls(
            device_id=device_id,
            role=role,
            public_identity_key=public_identity_key,
            public_encryption_key=public_encryption_key,
            identity_private_key_pem=_private_pem_text(identity_key),
            encryption_private_key_pem=_private_pem_text(encryption_key),
            fingerprint=fingerprint,
        )

    @classmethod
    def from_private_dict(cls, payload: Dict[str, object]) -> "MeshLocalIdentity":
        return cls(
            device_id=str(payload.get("device_id") or ""),
            role=str(payload.get("role") or ""),
            public_identity_key=str(payload.get("public_identity_key") or ""),
            public_encryption_key=str(payload.get("public_encryption_key") or ""),
            identity_private_key_pem=str(payload.get("identity_private_key_pem") or ""),
            encryption_private_key_pem=str(payload.get("encryption_private_key_pem") or ""),
            fingerprint=str(payload.get("fingerprint") or ""),
            created_at_utc=str(payload.get("created_at_utc") or utc_stamp()),
        )

    def to_private_dict(self) -> Dict[str, object]:
        return {
            "schema_version": SECURE_MESH_REGISTRY_SCHEMA,
            "protocol": SECURE_MESH_PROTOCOL,
            "record_type": "secure_mesh_local_identity_v1",
            "device_id": self.device_id,
            "role": self.role,
            "public_identity_key": self.public_identity_key,
            "public_encryption_key": self.public_encryption_key,
            "identity_private_key_pem": self.identity_private_key_pem,
            "encryption_private_key_pem": self.encryption_private_key_pem,
            "fingerprint": self.fingerprint,
            "created_at_utc": self.created_at_utc,
        }

    def to_public_record(
        self,
        *,
        allowed_actions: Optional[Iterable[str]] = None,
        allowed_tunnel_ip: str = "",
        transport_hints: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> MeshDeviceRecord:
        return MeshDeviceRecord.create(
            device_id=self.device_id,
            role=self.role,
            public_identity_key=self.public_identity_key,
            public_encryption_key=self.public_encryption_key,
            allowed_actions=allowed_actions,
            allowed_tunnel_ip=allowed_tunnel_ip,
            transport_hints=transport_hints,
            metadata=metadata,
        )


@dataclass
class MeshWireGuardIdentity:
    device_id: str
    private_key: str
    public_key: str
    address: str
    listen_port: int = DEFAULT_WIREGUARD_LISTEN_PORT
    endpoint: str = ""
    dns: str = ""
    created_at_utc: str = field(default_factory=utc_stamp)

    def __post_init__(self) -> None:
        self.device_id = normalize_device_id(self.device_id)
        self.private_key = str(self.private_key or "").strip()
        self.public_key = str(self.public_key or "").strip()
        self.address = str(self.address or "").strip()
        self.listen_port = int(self.listen_port or DEFAULT_WIREGUARD_LISTEN_PORT)
        self.endpoint = str(self.endpoint or "").strip()
        self.dns = str(self.dns or "").strip()
        if not self.private_key:
            raise ValueError("wireguard private_key is required")
        if not self.public_key:
            raise ValueError("wireguard public_key is required")
        if not self.address:
            raise ValueError("wireguard address is required")

    @classmethod
    def generate(
        cls,
        *,
        device_id: str,
        address: str,
        listen_port: int = DEFAULT_WIREGUARD_LISTEN_PORT,
        endpoint: str = "",
        dns: str = "",
    ) -> "MeshWireGuardIdentity":
        private_key, public_key = _wireguard_keypair()
        return cls(
            device_id=device_id,
            private_key=private_key,
            public_key=public_key,
            address=address,
            listen_port=listen_port,
            endpoint=endpoint,
            dns=dns,
        )

    @classmethod
    def from_private_dict(cls, payload: Dict[str, object]) -> "MeshWireGuardIdentity":
        return cls(
            device_id=str(payload.get("device_id") or ""),
            private_key=str(payload.get("private_key") or ""),
            public_key=str(payload.get("public_key") or ""),
            address=str(payload.get("address") or ""),
            listen_port=int(payload.get("listen_port", DEFAULT_WIREGUARD_LISTEN_PORT) or DEFAULT_WIREGUARD_LISTEN_PORT),
            endpoint=str(payload.get("endpoint") or ""),
            dns=str(payload.get("dns") or ""),
            created_at_utc=str(payload.get("created_at_utc") or utc_stamp()),
        )

    def to_private_dict(self) -> Dict[str, object]:
        return {
            "schema_version": SECURE_MESH_REGISTRY_SCHEMA,
            "protocol": SECURE_MESH_PROTOCOL,
            "record_type": WIREGUARD_IDENTITY_TYPE,
            "device_id": self.device_id,
            "private_key": self.private_key,
            "public_key": self.public_key,
            "address": self.address,
            "listen_port": self.listen_port,
            "endpoint": self.endpoint,
            "dns": self.dns,
            "created_at_utc": self.created_at_utc,
        }


@dataclass
class MeshRegistry:
    path: Path
    devices: Dict[str, MeshDeviceRecord] = field(default_factory=dict)
    schema_version: int = SECURE_MESH_REGISTRY_SCHEMA
    updated_at_utc: str = field(default_factory=utc_stamp)

    @classmethod
    def load(cls, path: Path) -> "MeshRegistry":
        selected = Path(path).expanduser().resolve()
        if not selected.exists():
            return cls(path=selected)
        with open(selected, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError(f"secure mesh registry must be a JSON object: {selected}")
        _assert_no_private_material(payload)
        devices_payload = payload.get("devices") or {}
        if isinstance(devices_payload, list):
            iterable = devices_payload
        elif isinstance(devices_payload, dict):
            iterable = devices_payload.values()
        else:
            raise ValueError("secure mesh registry devices must be an object or list")
        devices = {}
        for item in iterable:
            if not isinstance(item, dict):
                raise ValueError("secure mesh device records must be JSON objects")
            record = MeshDeviceRecord.from_dict(item)
            devices[record.device_id] = record
        return cls(
            path=selected,
            devices=devices,
            schema_version=int(payload.get("schema_version", SECURE_MESH_REGISTRY_SCHEMA) or SECURE_MESH_REGISTRY_SCHEMA),
            updated_at_utc=str(payload.get("updated_at_utc") or utc_stamp()),
        )

    def save(self) -> Path:
        self.updated_at_utc = utc_stamp()
        payload = self.to_public_dict()
        _assert_no_private_material(payload)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_name(f"{self.path.name}.tmp")
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        tmp_path.replace(self.path)
        return self.path

    def to_public_dict(self) -> Dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "protocol": SECURE_MESH_PROTOCOL,
            "updated_at_utc": self.updated_at_utc,
            "devices": {
                device_id: self.devices[device_id].to_public_dict()
                for device_id in sorted(self.devices)
            },
        }

    def add_device(self, record: MeshDeviceRecord, *, replace: bool = False) -> None:
        if record.device_id in self.devices and not replace:
            raise ValueError(f"secure mesh device already exists: {record.device_id}")
        self.devices[record.device_id] = record

    def get_device(self, device_id: str) -> Optional[MeshDeviceRecord]:
        return self.devices.get(normalize_device_id(device_id))

    def revoke(self, device_id: str, *, when_utc: Optional[str] = None) -> MeshDeviceRecord:
        record = self.get_device(device_id)
        if not record:
            raise KeyError(f"secure mesh device not found: {device_id}")
        record.revoked = True
        record.metadata["revoked_at_utc"] = when_utc or utc_stamp()
        return record

    def is_authorized(self, device_id: str, action: str) -> bool:
        record = self.get_device(device_id)
        return bool(record and record.allows(action))

    def list_devices(self, *, include_revoked: bool = True) -> List[MeshDeviceRecord]:
        records = sorted(self.devices.values(), key=lambda item: item.device_id)
        if include_revoked:
            return records
        return [record for record in records if not record.revoked]


def load_registry(config: Optional[Dict[str, object]] = None, *, path: Optional[Path] = None) -> MeshRegistry:
    return MeshRegistry.load(path or default_registry_path(config))


def init_registry(config: Optional[Dict[str, object]] = None, *, path: Optional[Path] = None) -> MeshRegistry:
    registry = load_registry(config, path=path)
    registry.save()
    return registry


def _write_json_private(path: Path, payload: Dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    try:
        tmp_path.chmod(0o600)
    except OSError:
        pass
    tmp_path.replace(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def generate_local_identity(
    config: Optional[Dict[str, object]],
    *,
    device_id: str,
    role: str,
    overwrite: bool = False,
    private_dir: Optional[Path] = None,
) -> MeshLocalIdentity:
    path = identity_path(config, device_id=device_id, private_dir=private_dir)
    if path.exists() and not overwrite:
        raise FileExistsError(f"secure mesh local identity already exists: {path}")
    identity = MeshLocalIdentity.generate(device_id=device_id, role=role)
    _write_json_private(path, identity.to_private_dict())
    return identity


def load_local_identity(
    config: Optional[Dict[str, object]],
    *,
    device_id: str,
    private_dir: Optional[Path] = None,
) -> MeshLocalIdentity:
    path = identity_path(config, device_id=device_id, private_dir=private_dir)
    if not path.exists():
        raise FileNotFoundError(f"secure mesh local identity not found: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"secure mesh local identity must be a JSON object: {path}")
    return MeshLocalIdentity.from_private_dict(payload)


def _command_key_material(
    *,
    local_identity: MeshLocalIdentity,
    peer_record: MeshDeviceRecord,
    sender_device_id: str,
    receiver_device_id: str,
    command: str,
) -> bytes:
    local_private = _load_x25519_private(local_identity.encryption_private_key_pem)
    peer_public = _load_x25519_public(peer_record.public_encryption_key)
    shared = local_private.exchange(peer_public)
    if local_identity.device_id == sender_device_id:
        sender_fingerprint = local_identity.fingerprint
        receiver_fingerprint = peer_record.fingerprint
    else:
        sender_fingerprint = peer_record.fingerprint
        receiver_fingerprint = local_identity.fingerprint
    salt = hashlib.blake2b(
        _canonical_json_bytes(
            {
                "protocol": SECURE_MESH_PROTOCOL,
                "purpose": "command-envelope",
                "sender": sender_device_id,
                "receiver": receiver_device_id,
                "sender_fingerprint": sender_fingerprint,
                "receiver_fingerprint": receiver_fingerprint,
            }
        ),
        digest_size=32,
        person=b"wifi-cmd-salt",
    ).digest()
    info = _canonical_json_bytes(
        {
            "envelope_type": COMMAND_ENVELOPE_TYPE,
            "sender": sender_device_id,
            "receiver": receiver_device_id,
            "command": command,
        }
    )
    return HKDF(algorithm=SHA256(), length=32, salt=salt, info=info).derive(shared)


def _verify_envelope_time(envelope: MeshCommandEnvelope, *, now: Optional[float] = None, max_clock_skew_seconds: int = 300) -> None:
    current = time.time() if now is None else float(now)
    created = _utc_to_epoch(envelope.created_at_utc)
    expires = _utc_to_epoch(envelope.expires_at_utc)
    if created > current + int(max_clock_skew_seconds):
        raise ValueError("secure mesh command was created in the future")
    if expires < current:
        raise ValueError("expired secure mesh command rejected")
    if expires < created:
        raise ValueError("secure mesh command expiry is before creation")


def _approval_expiry(issued_at_utc: str, ttl_seconds: int) -> str:
    return time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(_utc_to_epoch(issued_at_utc) + max(1, int(ttl_seconds))),
    )


def _wrap_body_with_approval(
    body: object,
    *,
    approval_code: str,
    sender_device_id: str,
    receiver_device_id: str,
    command: str,
    counter: int,
    message_id: str,
    issued_at_utc: str,
    ttl_seconds: int,
) -> Dict[str, object]:
    expires_at_utc = _approval_expiry(issued_at_utc, ttl_seconds)
    return {
        "secure_mesh_body_type": APPROVED_BODY_TYPE,
        "body": body,
        "approval": {
            "approval_hash": mesh_approval_hash(
                approval_code,
                sender_device_id=sender_device_id,
                receiver_device_id=receiver_device_id,
                command=command,
                counter=counter,
                message_id=message_id,
            ),
            "issued_at_utc": issued_at_utc,
            "expires_at_utc": expires_at_utc,
        },
    }


def _split_approved_body(decoded_body: object) -> Tuple[object, Optional[Dict[str, object]]]:
    if not isinstance(decoded_body, dict):
        return decoded_body, None
    if str(decoded_body.get("secure_mesh_body_type") or "") != APPROVED_BODY_TYPE:
        return decoded_body, None
    approval = decoded_body.get("approval")
    if not isinstance(approval, dict):
        raise ValueError("secure mesh command approval metadata is missing")
    return decoded_body.get("body"), dict(approval)


def _verify_mesh_approval(
    envelope: MeshCommandEnvelope,
    approval: Optional[Dict[str, object]],
    *,
    approval_code: str = "",
    required: bool = False,
    now: Optional[float] = None,
) -> None:
    if not required and approval is None:
        return
    if approval is None:
        raise ValueError("secure mesh command requires operator approval")
    code = str(approval_code or "").strip()
    if not code:
        raise ValueError("operator approval code is required for this secure mesh command")
    expires_at_utc = str(approval.get("expires_at_utc") or "").strip()
    if expires_at_utc and _utc_to_epoch(expires_at_utc) < (time.time() if now is None else float(now)):
        raise ValueError("expired secure mesh operator approval rejected")
    expected = mesh_approval_hash(
        code,
        sender_device_id=envelope.sender_device_id,
        receiver_device_id=envelope.receiver_device_id,
        command=envelope.command,
        counter=envelope.counter,
        message_id=envelope.message_id,
    )
    provided = str(approval.get("approval_hash") or "").strip()
    if not hmac.compare_digest(provided, expected):
        raise ValueError("secure mesh operator approval verification failed")


def seal_mesh_command(
    config: Optional[Dict[str, object]],
    *,
    sender_device_id: str,
    receiver_device_id: str,
    command: str,
    body: object,
    counter: int,
    ttl_seconds: int = 60,
    message_id: Optional[str] = None,
    created_at_utc: Optional[str] = None,
    approval_code: str = "",
    approval_ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS,
) -> MeshCommandEnvelope:
    sender_id = normalize_device_id(sender_device_id)
    receiver_id = normalize_device_id(receiver_device_id)
    registry = load_registry(config)
    sender_record = registry.get_device(sender_id)
    receiver_record = registry.get_device(receiver_id)
    if not sender_record:
        raise KeyError(f"secure mesh sender is not paired in the local registry: {sender_id}")
    if not receiver_record:
        raise KeyError(f"secure mesh receiver is not paired in the local registry: {receiver_id}")
    if sender_record.revoked:
        raise ValueError(f"secure mesh sender is revoked: {sender_id}")
    if receiver_record.revoked:
        raise ValueError(f"secure mesh receiver is revoked: {receiver_id}")
    if not sender_record.allows(command):
        raise ValueError(f"secure mesh sender {sender_id} is not authorized for command {command!r}")

    sender_identity = load_local_identity(config, device_id=sender_id)
    if sender_identity.public_identity_key != sender_record.public_identity_key:
        raise ValueError("local sender identity does not match paired registry identity key")
    if sender_identity.public_encryption_key != sender_record.public_encryption_key:
        raise ValueError("local sender identity does not match paired registry encryption key")

    created = created_at_utc or utc_stamp()
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(_utc_to_epoch(created) + max(1, int(ttl_seconds))))
    resolved_message_id = message_id or secrets.token_hex(16)
    metadata = {
        "protocol": SECURE_MESH_PROTOCOL,
        "envelope_type": COMMAND_ENVELOPE_TYPE,
        "sender_device_id": sender_id,
        "receiver_device_id": receiver_id,
        "command": str(command or "").strip(),
        "message_id": resolved_message_id,
        "counter": int(counter),
        "created_at_utc": created,
        "expires_at_utc": expires,
    }
    body_to_encrypt = body
    if str(approval_code or "").strip():
        body_to_encrypt = _wrap_body_with_approval(
            body,
            approval_code=str(approval_code),
            sender_device_id=sender_id,
            receiver_device_id=receiver_id,
            command=str(command or "").strip(),
            counter=int(counter),
            message_id=resolved_message_id,
            issued_at_utc=created,
            ttl_seconds=approval_ttl_seconds,
        )
    aad = _canonical_json_bytes(metadata)
    key = _command_key_material(
        local_identity=sender_identity,
        peer_record=receiver_record,
        sender_device_id=sender_id,
        receiver_device_id=receiver_id,
        command=str(command or "").strip(),
    )
    nonce = secrets.token_bytes(COMMAND_NONCE_BYTES)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, _body_to_bytes(body_to_encrypt), aad)
    unsigned = dict(metadata)
    unsigned.update(
        {
            "nonce": _b64url(nonce),
            "ciphertext": _b64url(ciphertext),
            "associated_data": _b64url(aad),
        }
    )
    signature = _load_ed25519_private(sender_identity.identity_private_key_pem).sign(_canonical_json_bytes(unsigned))
    return MeshCommandEnvelope.from_dict({**unsigned, "signature": _b64url(signature)})


def open_mesh_command(
    config: Optional[Dict[str, object]],
    envelope_payload: Dict[str, object] | MeshCommandEnvelope,
    *,
    receiver_device_id: str,
    replay_cache: Optional[MeshReplayCache] = None,
    now: Optional[float] = None,
    approval_code: str = "",
    require_approval: bool = False,
) -> Tuple[MeshCommandEnvelope, object]:
    envelope = envelope_payload if isinstance(envelope_payload, MeshCommandEnvelope) else MeshCommandEnvelope.from_dict(envelope_payload)
    receiver_id = normalize_device_id(receiver_device_id)
    if envelope.receiver_device_id != receiver_id:
        raise ValueError("secure mesh command receiver mismatch")
    _verify_envelope_time(envelope, now=now)

    registry = load_registry(config)
    sender_record = registry.get_device(envelope.sender_device_id)
    receiver_record = registry.get_device(receiver_id)
    if not sender_record:
        raise KeyError(f"secure mesh sender is not paired in the local registry: {envelope.sender_device_id}")
    if not receiver_record:
        raise KeyError(f"secure mesh receiver is not paired in the local registry: {receiver_id}")
    if sender_record.revoked:
        raise ValueError(f"secure mesh sender is revoked: {sender_record.device_id}")
    if receiver_record.revoked:
        raise ValueError(f"secure mesh receiver is revoked: {receiver_record.device_id}")
    if not sender_record.allows(envelope.command):
        raise ValueError(f"secure mesh sender {sender_record.device_id} is not authorized for command {envelope.command!r}")

    try:
        _load_ed25519_public(sender_record.public_identity_key).verify(
            _b64url_decode(envelope.signature),
            _canonical_json_bytes(envelope.signed_payload()),
        )
    except InvalidSignature as exc:
        raise ValueError("secure mesh command signature verification failed") from exc

    expected_aad = _canonical_json_bytes(envelope.metadata())
    if _b64url_decode(envelope.associated_data) != expected_aad:
        raise ValueError("secure mesh command associated data mismatch")

    receiver_identity = load_local_identity(config, device_id=receiver_id)
    if receiver_identity.public_identity_key != receiver_record.public_identity_key:
        raise ValueError("local receiver identity does not match paired registry identity key")
    if receiver_identity.public_encryption_key != receiver_record.public_encryption_key:
        raise ValueError("local receiver identity does not match paired registry encryption key")

    key = _command_key_material(
        local_identity=receiver_identity,
        peer_record=sender_record,
        sender_device_id=envelope.sender_device_id,
        receiver_device_id=receiver_id,
        command=envelope.command,
    )
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(
            _b64url_decode(envelope.nonce),
            _b64url_decode(envelope.ciphertext),
            expected_aad,
        )
    except InvalidTag as exc:
        raise ValueError("secure mesh command decryption failed") from exc
    decoded_body = _json_or_text(plaintext)
    body, approval = _split_approved_body(decoded_body)
    approval_required = bool(require_approval) or (
        bool((config or {}).get("secure_mesh_require_approval_for_sensitive", False))
        and is_sensitive_mesh_command(envelope.command, config)
    )
    _verify_mesh_approval(
        envelope,
        approval,
        approval_code=approval_code,
        required=approval_required,
        now=now,
    )
    if replay_cache is not None:
        replay_cache.check_and_record(envelope)
    return envelope, body


def write_mesh_command_bundle(
    envelopes: Iterable[Dict[str, object] | MeshCommandEnvelope],
    path: Path,
    *,
    route_hint: str = "",
    created_at_utc: Optional[str] = None,
) -> Path:
    normalized = [
        (envelope if isinstance(envelope, MeshCommandEnvelope) else MeshCommandEnvelope.from_dict(envelope)).to_dict()
        for envelope in envelopes
    ]
    if not normalized:
        raise ValueError("secure mesh command bundle requires at least one envelope")
    payload = {
        "schema_version": SECURE_MESH_REGISTRY_SCHEMA,
        "protocol": SECURE_MESH_PROTOCOL,
        "bundle_type": COMMAND_BUNDLE_TYPE,
        "created_at_utc": created_at_utc or utc_stamp(),
        "route_hint": str(route_hint or "").strip(),
        "envelopes": normalized,
    }
    _assert_no_private_material(payload)
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return target


def load_mesh_command_bundle(path: Path) -> List[MeshCommandEnvelope]:
    selected = Path(path).expanduser().resolve()
    with open(selected, "r", encoding="utf-8-sig") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("secure mesh command bundle must be a JSON object")
    _assert_no_private_material(payload)
    if str(payload.get("protocol") or "") != SECURE_MESH_PROTOCOL:
        raise ValueError("unsupported secure mesh command bundle protocol")
    if str(payload.get("bundle_type") or "") != COMMAND_BUNDLE_TYPE:
        raise ValueError("unsupported secure mesh command bundle type")
    envelopes = payload.get("envelopes") or []
    if not isinstance(envelopes, list):
        raise ValueError("secure mesh command bundle envelopes must be a list")
    return [MeshCommandEnvelope.from_dict(dict(item)) for item in envelopes]


def mesh_command_bundle_summary(envelopes: Iterable[MeshCommandEnvelope]) -> List[Dict[str, object]]:
    return [envelope.metadata() for envelope in envelopes]


def init_wireguard_identity(
    config: Optional[Dict[str, object]],
    *,
    device_id: str,
    address: str,
    listen_port: int = DEFAULT_WIREGUARD_LISTEN_PORT,
    endpoint: str = "",
    dns: str = "",
    overwrite: bool = False,
    private_dir: Optional[Path] = None,
) -> MeshWireGuardIdentity:
    path = wireguard_identity_path(config, device_id=device_id, private_dir=private_dir)
    if path.exists() and not overwrite:
        raise FileExistsError(f"secure mesh WireGuard identity already exists: {path}")
    registry = load_registry(config)
    record = registry.get_device(device_id)
    if not record:
        raise KeyError("secure mesh device must exist in the registry before WireGuard bootstrap; run mesh init-identity or add-device first")
    identity = MeshWireGuardIdentity.generate(
        device_id=device_id,
        address=address,
        listen_port=listen_port,
        endpoint=endpoint,
        dns=dns,
    )
    _write_json_private(path, identity.to_private_dict())
    record.metadata["wireguard_public_key"] = identity.public_key
    record.metadata["wireguard_listen_port"] = str(identity.listen_port)
    if identity.dns:
        record.metadata["wireguard_dns"] = identity.dns
    record.allowed_tunnel_ip = _wireguard_allowed_ip(identity.address)
    record.transport_hints["wireguard"] = identity.address
    if identity.endpoint:
        record.transport_hints["wireguard_endpoint"] = identity.endpoint
    registry.add_device(record, replace=True)
    registry.save()
    return identity


def load_wireguard_identity(
    config: Optional[Dict[str, object]],
    *,
    device_id: str,
    private_dir: Optional[Path] = None,
) -> MeshWireGuardIdentity:
    path = wireguard_identity_path(config, device_id=device_id, private_dir=private_dir)
    if not path.exists():
        raise FileNotFoundError(f"secure mesh WireGuard identity not found: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"secure mesh WireGuard identity must be a JSON object: {path}")
    return MeshWireGuardIdentity.from_private_dict(payload)


def _wireguard_peer_allowed_ips(peer: MeshDeviceRecord) -> str:
    if peer.allowed_tunnel_ip:
        return peer.allowed_tunnel_ip
    for key in ("wireguard", "tunnel_ip"):
        value = str(peer.transport_hints.get(key) or "").strip()
        if value:
            return _wireguard_allowed_ip(value)
    return ""


def render_wireguard_config(
    config: Optional[Dict[str, object]],
    *,
    device_id: str,
    peer_device_id: str,
    persistent_keepalive: int = 25,
) -> str:
    identity = load_wireguard_identity(config, device_id=device_id)
    registry = load_registry(config)
    peer = registry.get_device(peer_device_id)
    if not peer:
        raise KeyError(f"secure mesh peer not found: {peer_device_id}")
    if peer.revoked:
        raise ValueError(f"secure mesh peer is revoked: {peer_device_id}")
    peer_public_key = str(peer.metadata.get("wireguard_public_key") or "").strip()
    if not peer_public_key:
        raise ValueError(f"secure mesh peer does not have a WireGuard public key: {peer_device_id}")
    allowed_ips = _wireguard_peer_allowed_ips(peer)
    if not allowed_ips:
        raise ValueError(f"secure mesh peer does not have a WireGuard tunnel IP: {peer_device_id}")
    endpoint = str(peer.transport_hints.get("wireguard_endpoint") or "").strip()

    lines = [
        "[Interface]",
        f"PrivateKey = {identity.private_key}",
        f"Address = {identity.address}",
    ]
    if identity.listen_port:
        lines.append(f"ListenPort = {identity.listen_port}")
    if identity.dns:
        lines.append(f"DNS = {identity.dns}")
    lines.extend(
        [
            "",
            "[Peer]",
            f"# Device = {peer.device_id}",
            f"PublicKey = {peer_public_key}",
            f"AllowedIPs = {allowed_ips}",
        ]
    )
    if endpoint:
        lines.append(f"Endpoint = {endpoint}")
    if persistent_keepalive > 0:
        lines.append(f"PersistentKeepalive = {int(persistent_keepalive)}")
    return "\n".join(lines) + "\n"


def public_pairing_bundle(
    identity: MeshLocalIdentity,
    *,
    allowed_actions: Optional[Iterable[str]] = None,
    allowed_tunnel_ip: str = "",
    transport_hints: Optional[Dict[str, str]] = None,
    metadata: Optional[Dict[str, str]] = None,
) -> Dict[str, object]:
    record = identity.to_public_record(
        allowed_actions=allowed_actions,
        allowed_tunnel_ip=allowed_tunnel_ip,
        transport_hints=transport_hints,
        metadata=metadata,
    )
    payload = {
        "schema_version": SECURE_MESH_REGISTRY_SCHEMA,
        "protocol": SECURE_MESH_PROTOCOL,
        "bundle_type": PAIRING_BUNDLE_TYPE,
        "created_at_utc": utc_stamp(),
        "device": record.to_public_dict(),
    }
    _assert_no_private_material(payload)
    return payload


def write_pairing_bundle(
    identity: MeshLocalIdentity,
    path: Path,
    *,
    allowed_actions: Optional[Iterable[str]] = None,
    allowed_tunnel_ip: str = "",
    transport_hints: Optional[Dict[str, str]] = None,
    metadata: Optional[Dict[str, str]] = None,
) -> Path:
    payload = public_pairing_bundle(
        identity,
        allowed_actions=allowed_actions,
        allowed_tunnel_ip=allowed_tunnel_ip,
        transport_hints=transport_hints,
        metadata=metadata,
    )
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return target


def load_pairing_bundle(path: Path) -> MeshDeviceRecord:
    selected = Path(path).expanduser().resolve()
    with open(selected, "r", encoding="utf-8-sig") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("secure mesh pairing bundle must be a JSON object")
    _assert_no_private_material(payload)
    if str(payload.get("protocol") or "") != SECURE_MESH_PROTOCOL:
        raise ValueError("unsupported secure mesh pairing bundle protocol")
    if str(payload.get("bundle_type") or "") != PAIRING_BUNDLE_TYPE:
        raise ValueError("unsupported secure mesh pairing bundle type")
    device = payload.get("device")
    if not isinstance(device, dict):
        raise ValueError("secure mesh pairing bundle is missing a public device record")
    return MeshDeviceRecord.from_dict(device)


def import_pairing_bundle(
    config: Optional[Dict[str, object]],
    *,
    bundle_path: Path,
    expected_fingerprint: str,
    replace: bool = False,
) -> MeshDeviceRecord:
    record = load_pairing_bundle(bundle_path)
    expected = str(expected_fingerprint or "").strip()
    if not expected:
        raise ValueError("expected fingerprint is required before trusting a pairing bundle")
    if expected != record.fingerprint:
        raise ValueError("pairing bundle fingerprint does not match the verified fingerprint")
    registry = load_registry(config)
    registry.add_device(record, replace=replace)
    registry.save()
    return record


def _record_transport_hints(record: MeshDeviceRecord) -> List[MeshTransportHint]:
    hints: List[MeshTransportHint] = []
    for key, value in sorted(record.transport_hints.items()):
        target = str(value or "").strip()
        if not target:
            continue
        transport_type = _normalize_transport_type(key)
        hints.append(
            MeshTransportHint(
                transport_type=transport_type,
                target=target,
                status="configured",
                source="registry",
                detail="Paired registry transport hint.",
            )
        )
    if record.allowed_tunnel_ip:
        hints.append(
            MeshTransportHint(
                transport_type="wireguard",
                target=record.allowed_tunnel_ip,
                status="configured",
                source="registry",
                detail="Paired registry tunnel IP.",
            )
        )
    return hints


def _registry_match_for_hint(
    registry: MeshRegistry,
    *,
    fingerprint_hint: str = "",
    device_id_hint: str = "",
    target_hint: str = "",
) -> tuple[Optional[MeshDeviceRecord], str]:
    fingerprint = str(fingerprint_hint or "").strip()
    if fingerprint:
        for record in registry.devices.values():
            if record.fingerprint == fingerprint:
                return record, "fingerprint"
        return None, "fingerprint_miss"

    device_id = str(device_id_hint or "").strip()
    if device_id and device_id in registry.devices:
        return registry.devices[device_id], "device_id_hint"

    target_host = _host_without_user(target_hint)
    target_text = str(target_hint or "").strip().lower()
    if target_host:
        for record in registry.devices.values():
            for key, value in record.transport_hints.items():
                if _host_without_user(value) == target_host or str(value or "").strip().lower() == target_text:
                    return record, "transport_hint"
            if record.allowed_tunnel_ip and (
                _host_without_user(record.allowed_tunnel_ip) == target_host
                or record.allowed_tunnel_ip.strip().lower() == target_text
            ):
                return record, "transport_hint"
    return None, ""


def _trust_from_match(
    record: Optional[MeshDeviceRecord],
    match_kind: str,
    *,
    fingerprint_hint: str = "",
) -> tuple[bool, str, str, str, bool]:
    if not record:
        if fingerprint_hint and match_kind == "fingerprint_miss":
            return False, "unknown_fingerprint", "Fingerprint hint is not paired in the local registry.", "", False
        return False, "untrusted", "Discovery is only a hint until a paired fingerprint matches.", "", False
    if record.revoked:
        return False, "revoked", "Matched device is revoked in the local registry.", record.device_id, True
    if match_kind == "fingerprint":
        return True, "trusted", "Fingerprint matches a paired device in the local registry.", record.device_id, False
    if match_kind == "transport_hint":
        return False, "known_route_hint", "Route target matches a paired record, but no fingerprint was presented.", record.device_id, False
    if match_kind == "device_id_hint":
        return False, "known_device_id_hint", "Device id matches a paired record, but no fingerprint was presented.", record.device_id, False
    return False, "untrusted", "Discovery is only a hint until a paired fingerprint matches.", "", False


def _discovery_record_for_registry_device(record: MeshDeviceRecord) -> MeshDiscoveryRecord:
    trusted = not record.revoked
    return MeshDiscoveryRecord(
        source="registry",
        device_id_hint=record.device_id,
        fingerprint_hint=record.fingerprint,
        trusted=trusted,
        trust_status="trusted" if trusted else "revoked",
        trust_reason="Paired local registry record." if trusted else "Device is revoked in the local registry.",
        matched_device_id=record.device_id,
        revoked=record.revoked,
        transports=_record_transport_hints(record),
        metadata={"role": record.role},
    )


def _discovery_record_for_configured_remote(config: Dict[str, object], registry: MeshRegistry) -> Optional[MeshDiscoveryRecord]:
    remote_host = str(config.get("remote_host") or "").strip()
    if not remote_host:
        return None
    record, match_kind = _registry_match_for_hint(registry, target_hint=remote_host)
    trusted, trust_status, trust_reason, matched_device_id, revoked = _trust_from_match(record, match_kind)
    transports = [
        MeshTransportHint(
            transport_type="ssh",
            target=remote_host,
            status="configured",
            source="config",
            detail="Configured remote_host from lab config.",
        )
    ]
    remote_path = str(config.get("remote_path") or "").strip()
    if remote_path:
        transports.append(
            MeshTransportHint(
                transport_type="remote_capture_path",
                target=remote_path,
                status="configured",
                source="config",
                detail="Configured remote capture path.",
            )
        )
    return MeshDiscoveryRecord(
        source="config",
        device_id_hint=matched_device_id,
        fingerprint_hint=str(record.fingerprint if record else ""),
        trusted=trusted,
        trust_status=trust_status,
        trust_reason=trust_reason,
        matched_device_id=matched_device_id,
        revoked=revoked,
        transports=transports,
    )


def _mesh_hint(record: Dict[str, str], *keys: str) -> str:
    for key in keys:
        value = str(record.get(key) or "").strip()
        if value:
            return value
    return ""


def parse_mesh_transport_hint(
    text: str,
    *,
    device_id_hint: str = "",
    fingerprint_hint: str = "",
    source: str = "operator_hint",
) -> Dict[str, str]:
    value = str(text or "").strip()
    if "=" not in value:
        raise ValueError("secure mesh transport hints must use TYPE=TARGET, for example bluetooth=AA:BB or serial=COM4")
    transport, target = [part.strip() for part in value.split("=", 1)]
    transport_type = _normalize_transport_type(transport)
    if transport_type not in TRANSPORT_PRIORITIES:
        raise ValueError(f"unknown secure mesh transport hint type: {transport}")
    if not target:
        raise ValueError("secure mesh transport hint target is required")
    payload = {
        "transport_type": transport_type,
        "target": target,
        "source": source,
    }
    if device_id_hint:
        payload["device_id"] = str(device_id_hint).strip()
    if fingerprint_hint:
        payload["fingerprint"] = str(fingerprint_hint).strip()
    return payload


def load_mesh_discovery_hint_file(path: Path) -> List[Dict[str, str]]:
    selected = Path(path).expanduser().resolve()
    with open(selected, "r", encoding="utf-8-sig") as handle:
        payload = json.load(handle)
    if isinstance(payload, dict) and "hints" in payload:
        raw_items = payload.get("hints") or []
    elif isinstance(payload, list):
        raw_items = payload
    elif isinstance(payload, dict):
        raw_items = [payload]
    else:
        raise ValueError(f"secure mesh discovery hint file must contain an object, a list, or a hints list: {selected}")
    hints: List[Dict[str, str]] = []
    for item in list(raw_items or []):
        if not isinstance(item, dict):
            raise ValueError(f"secure mesh discovery hints must be JSON objects: {selected}")
        _assert_no_private_material(item)
        hints.append({str(key): str(value) for key, value in item.items() if value is not None})
    return hints


def _coerce_discovery_hints(raw: object, *, source: str) -> List[Dict[str, str]]:
    if raw in (None, "", []):
        return []
    if isinstance(raw, str):
        return [parse_mesh_transport_hint(raw, source=source)]
    if isinstance(raw, dict):
        if "hints" in raw:
            raw = raw.get("hints") or []
        else:
            _assert_no_private_material(raw)
            payload = {str(key): str(value) for key, value in raw.items() if value is not None}
            payload.setdefault("source", source)
            return [payload]
    if not isinstance(raw, (list, tuple)):
        raise ValueError("secure mesh discovery hints must be a TYPE=TARGET string, JSON object, or list")
    hints: List[Dict[str, str]] = []
    for item in list(raw or []):
        if isinstance(item, str):
            hints.append(parse_mesh_transport_hint(item, source=source))
            continue
        if not isinstance(item, dict):
            raise ValueError("secure mesh discovery hints must be TYPE=TARGET strings or JSON objects")
        _assert_no_private_material(item)
        payload = {str(key): str(value) for key, value in item.items() if value is not None}
        payload.setdefault("source", source)
        hints.append(payload)
    return hints


def _coerce_string_list(raw: object) -> List[str]:
    if raw in (None, "", []):
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, (list, tuple)):
        return [str(item) for item in raw if str(item or "").strip()]
    raise ValueError("secure mesh discovery hint file paths must be a string or list")


def _transport_hint_status(payload: Dict[str, str], *, source: str, key: str = "") -> str:
    status = _mesh_hint(payload, "status")
    if status:
        return status
    if source == "appliance_discovery" and key in ("ssh_target", "health_endpoint"):
        return "reachable"
    return "detected"


def _transport_hints_from_discovery_payload(payload: Dict[str, str], *, source: str) -> List[MeshTransportHint]:
    hints: List[MeshTransportHint] = []
    seen: set[tuple[str, str]] = set()

    def add_hint(transport_type: str, target: str, *, key: str = "", detail: str = "") -> None:
        normalized_type = _normalize_transport_type(transport_type)
        clean_target = str(target or "").strip()
        if not clean_target:
            return
        dedupe_key = (normalized_type, clean_target)
        if dedupe_key in seen:
            return
        seen.add(dedupe_key)
        hints.append(
            MeshTransportHint(
                transport_type=normalized_type,
                target=clean_target,
                status=_transport_hint_status(payload, source=source, key=key),
                source=source,
                detail=_mesh_hint(payload, "detail") or detail or "Transport-independent discovery hint. Never a trust boundary.",
            )
        )

    explicit_transport = _mesh_hint(payload, "transport", "transport_type", "type")
    explicit_target = _mesh_hint(payload, "target", "value", "address", "endpoint")
    if explicit_transport and explicit_target:
        add_hint(explicit_transport, explicit_target)

    for key, (transport_type, detail) in DISCOVERY_HINT_TRANSPORT_FIELDS.items():
        value = _mesh_hint(payload, key)
        if value:
            add_hint(transport_type, value, key=key, detail=detail)
    return sorted(hints, key=lambda item: (item.priority, item.transport_type, item.target))


def _discovery_metadata(payload: Dict[str, str]) -> Dict[str, str]:
    excluded = set(DISCOVERY_HINT_TRANSPORT_FIELDS)
    excluded.update(DISCOVERY_IDENTITY_HINT_KEYS)
    excluded.update({"transport", "transport_type", "type", "target", "value", "address", "endpoint", "status", "source", "detail"})
    return {
        str(key): str(value)
        for key, value in payload.items()
        if str(key) not in excluded
    }


def _discovery_record_for_transport_hint(
    hint: Dict[str, str],
    registry: MeshRegistry,
    *,
    source: str = "transport_hint",
    allow_empty: bool = False,
) -> Optional[MeshDiscoveryRecord]:
    _assert_no_private_material(hint)
    active_source = str(hint.get("source") or source or "transport_hint").strip()
    fingerprint = _mesh_hint(hint, "secure_mesh_fingerprint", "mesh_fingerprint", "fingerprint")
    device_id = _mesh_hint(hint, "secure_mesh_device_id", "mesh_device_id", "device_id", "device_name", "host")
    transports = _transport_hints_from_discovery_payload(hint, source=active_source)
    if not transports and not allow_empty:
        return None
    target_hint = _mesh_hint(hint, "target", "value", "address", "endpoint") or (transports[0].target if transports else "")
    record, match_kind = _registry_match_for_hint(
        registry,
        fingerprint_hint=fingerprint,
        device_id_hint=device_id,
        target_hint=target_hint,
    )
    trusted, trust_status, trust_reason, matched_device_id, revoked = _trust_from_match(
        record,
        match_kind,
        fingerprint_hint=fingerprint,
    )
    return MeshDiscoveryRecord(
        source=active_source,
        device_id_hint=device_id,
        fingerprint_hint=fingerprint,
        trusted=trusted,
        trust_status=trust_status,
        trust_reason=trust_reason,
        matched_device_id=matched_device_id,
        revoked=revoked,
        transports=transports,
        metadata=_discovery_metadata(hint),
    )


def _discovery_record_for_appliance(appliance: Dict[str, str], registry: MeshRegistry) -> MeshDiscoveryRecord:
    return _discovery_record_for_transport_hint(
        appliance,
        registry,
        source="appliance_discovery",
        allow_empty=True,
    ) or MeshDiscoveryRecord(source="appliance_discovery")


def discover_mesh_devices(
    config: Optional[Dict[str, object]] = None,
    *,
    appliance_nodes: Optional[List[Dict[str, str]]] = None,
    appliance_discovery_fn=None,
    transport_hints: Optional[List[Dict[str, str]]] = None,
    hint_files: Optional[List[str]] = None,
    networks: Optional[List[str]] = None,
    health_port: Optional[int] = None,
    timeout: float = 0.35,
    max_hosts: int = 64,
    include_registry: bool = True,
) -> List[MeshDiscoveryRecord]:
    active_config = dict(config or {})
    registry = load_registry(active_config)
    records: List[MeshDiscoveryRecord] = []
    if include_registry:
        records.extend(_discovery_record_for_registry_device(record) for record in registry.list_devices())

    configured = _discovery_record_for_configured_remote(active_config, registry)
    if configured:
        records.append(configured)

    configured_hints = _coerce_discovery_hints(active_config.get("secure_mesh_discovery_hints"), source="config_hint")
    hint_file_paths = _coerce_string_list(active_config.get("secure_mesh_discovery_hint_files")) + _coerce_string_list(hint_files)
    file_hints: List[Dict[str, str]] = []
    for hint_file in hint_file_paths:
        for item in load_mesh_discovery_hint_file(Path(str(hint_file))):
            item.setdefault("source", "hint_file")
            file_hints.append(item)
    explicit_hints = _coerce_discovery_hints(transport_hints or [], source="operator_hint")
    for hint in configured_hints + file_hints + explicit_hints:
        record = _discovery_record_for_transport_hint(hint, registry)
        if record:
            records.append(record)

    nodes = appliance_nodes
    if nodes is None:
        if appliance_discovery_fn is None:
            from .remote_discovery import discover_remote_appliances

            appliance_discovery_fn = discover_remote_appliances
        nodes = appliance_discovery_fn(
            active_config,
            networks=networks,
            health_port=health_port,
            timeout=timeout,
            max_hosts=max_hosts,
        )
    for appliance in list(nodes or []):
        records.append(_discovery_record_for_appliance(dict(appliance), registry))

    return sorted(
        records,
        key=lambda item: (
            0 if item.trusted and not item.revoked else 1,
            0 if item.best_transport() else 1,
            item.best_transport().priority if item.best_transport() else 999,
            item.matched_device_id or item.device_id_hint or item.source,
        ),
    )


def mesh_paths_for_device(records: List[MeshDiscoveryRecord], device_id: str) -> List[MeshDiscoveryRecord]:
    target = normalize_device_id(device_id)
    return [
        record
        for record in records
        if record.matched_device_id == target or record.device_id_hint == target
    ]


def select_mesh_route(
    records: List[MeshDiscoveryRecord],
    device_id: str,
    *,
    allowed_transports: Optional[Iterable[str]] = None,
    require_trusted: bool = True,
) -> MeshRoutePlan:
    target = normalize_device_id(device_id)
    allowed = [_normalize_transport_type(item) for item in list(allowed_transports or []) if str(item or "").strip()]
    candidate_records = mesh_paths_for_device(records, target)
    if not candidate_records:
        return MeshRoutePlan(
            device_id=target,
            selected=False,
            reason="No discovery records matched the requested device.",
            require_trusted=require_trusted,
            allowed_transports=allowed,
        )

    candidates: List[tuple[MeshDiscoveryRecord, MeshTransportHint]] = []
    blocked_untrusted = False
    blocked_transport = False
    blocked_missing_transport = False
    for record in candidate_records:
        if record.revoked:
            continue
        if require_trusted and not record.trusted:
            blocked_untrusted = True
            continue
        transports = list(record.transports or [])
        if not transports:
            blocked_missing_transport = True
            continue
        for transport in transports:
            if allowed and transport.transport_type not in allowed:
                blocked_transport = True
                continue
            candidates.append((record, transport))

    if not candidates:
        if blocked_untrusted:
            reason = "Matching route hints exist, but none are trusted by paired fingerprint."
        elif blocked_transport:
            reason = "Matching route hints exist, but none use an allowed transport."
        elif blocked_missing_transport:
            reason = "Matching device records exist, but no transport target is available."
        else:
            reason = "No usable route is available for the requested device."
        return MeshRoutePlan(
            device_id=target,
            selected=False,
            reason=reason,
            require_trusted=require_trusted,
            allowed_transports=allowed,
        )

    record, transport = sorted(
        candidates,
        key=lambda item: (
            item[1].priority,
            0 if item[1].status in ("reachable", "configured", "detected") else 50,
            item[1].transport_type,
            item[1].target,
        ),
    )[0]
    return MeshRoutePlan(
        device_id=target,
        selected=True,
        transport=transport,
        discovery=record,
        reason="Selected best trusted route." if require_trusted else "Selected best available route.",
        require_trusted=require_trusted,
        allowed_transports=allowed,
    )
