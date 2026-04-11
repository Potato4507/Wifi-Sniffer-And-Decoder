# Secure Device Mesh

This is the proposed direction for letting two trusted devices find each other and interact with the pipeline over any untrusted transport: Wi-Fi, hotspot, Ethernet, Bluetooth, radio, or a cable. The transport is treated as hostile. Trust comes from device keys and encrypted pipeline sessions, not from the network.

## Core idea

The safest design is a layered secure mesh:

1. A device identity layer proves "this is the same paired device as before."
2. A tunnel layer encrypts all traffic before pipeline services are reachable.
3. A pipeline message layer authenticates commands, artifacts, and status updates end to end.

This means normal Wi-Fi security is no longer the root of trust. Wi-Fi can be open, weak, captive, hotspot-based, or replaced by another transport, and the pipeline should still require device keys before accepting useful traffic.

## Phase 1 status

Phase 1 is the security boundary and threat model. It is complete when future mesh work can answer these questions before code is merged:

- What asset is protected?
- Which device identities are allowed to access it?
- Which transport assumptions are forbidden?
- Which replay, impersonation, downgrade, and secret-leak checks must pass?
- Which behavior is intentionally out of scope?

No secure mesh implementation should be accepted until it satisfies the rules in this document.

## Phase 2 status

Phase 2 adds the local secure mesh foundation:

- `wifi_pipeline.secure_mesh` stores public paired-device records.
- `lab.json` gets only public/local mesh pointers, not private keys.
- The default public registry path is `./pipeline_output/secure_mesh/devices.json`.
- The default future private-key directory is `~/.wifi-pipeline/secure_mesh`.
- Device IDs, roles, fingerprints, permissions, revocation state, and public transport hints are represented.
- Registry loading rejects secret-looking fields such as private keys, PSKs, pairing tokens, seeds, and mnemonics.
- CLI support exists for `mesh init`, `mesh devices`, `mesh add-device`, and `mesh revoke`.

Phase 2 intentionally does not generate keys, pair devices, encrypt messages, or configure WireGuard yet. Those start in later phases.

## Phase 3 status

Phase 3 adds local pairing and key-material primitives:

- Local identities now generate Ed25519 identity keys and X25519 encryption keys.
- Private identity files are stored under `secure_mesh_private_dir`, defaulting to `~/.wifi-pipeline/secure_mesh`.
- Private key material is never written to `lab.json`, pairing bundles, public registries, dashboard HTML, or reports.
- Public pairing bundles can be exported for trusted out-of-band transfer.
- Pairing bundle imports require an out-of-band verified fingerprint through `--trust-fingerprint`.
- One-time pairing tokens can be issued for manual/QR verification flows; tokens are shown once and not stored.
- The local registry can add this device's public identity record after key generation.

Phase 3 intentionally does not yet send encrypted pipeline messages or configure a transport. It prepares the identity, fingerprint, and public-bundle flow that encrypted command envelopes will use.

## Phase 4 status

Phase 4 adds automatic discovery and route inventory:

- `mesh discover` finds possible devices and connection paths from the paired registry, saved remote config, and appliance health discovery.
- `mesh paths --device <id>` filters discovery records down to one paired device.
- Discovery records can include SSH targets, public health endpoints, WireGuard tunnel hints, hotspot SSIDs, and future Bluetooth/serial/radio hints.
- Route ranking prefers trusted paired records and stronger transports such as WireGuard before SSH and public health hints.
- A discovery hint is trusted only when its fingerprint matches a paired, non-revoked registry record.
- Device-name, hostname, IP-address, SSID, or transport-target matches are treated as hints, not identity.
- Revoked fingerprints stay untrusted even when the discovered route is reachable.

Phase 4 intentionally does not yet execute remote commands over these routes. It only answers: "what devices might be nearby, what paths might work, and which of those hints match paired trust?"

## Phase 5 status

Phase 5 adds WireGuard-first secure transport bootstrap:

- `mesh wg-init` generates local WireGuard key material for a paired device record.
- WireGuard private keys are stored under `secure_mesh_private_dir`, not in `lab.json` or public registries.
- The paired registry stores only public WireGuard metadata: public key, tunnel address, listen port, endpoint hints, and optional DNS hints.
- `mesh export-bundle` includes the local public WireGuard metadata when the registry has it, so peers can import it without receiving private keys.
- `mesh wg-render` renders a WireGuard config for one local device and one paired peer.
- Rendered configs are written only when the operator asks for them; the project does not silently install or enable OS network interfaces.

Phase 5 intentionally does not yet route pipeline commands through WireGuard automatically. It prepares the transport config material and keeps installation/operator approval explicit.

## Phase 6 status

Phase 6 adds custom pipeline command encryption above any transport:

- `mesh seal-command` creates signed and encrypted command envelopes from an already-paired local device to a paired receiver.
- `mesh open-command` verifies sender, receiver, protocol version, signature, expiry, revocation state, role permissions, replay state, and associated data before returning the decrypted body.
- Command bodies are encrypted client-side before the envelope can be moved over Wi-Fi, hotspot, WireGuard, SSH, serial, Bluetooth, radio, or a store-and-forward file.
- Envelopes use the project's custom packet format with reviewed primitives: X25519 key agreement, HKDF-SHA256 key derivation, ChaCha20-Poly1305 AEAD, and Ed25519 signatures.
- Replay protection tracks message IDs, monotonic sender-to-receiver counters, and AEAD nonces for the same sender, receiver, and command.
- The default replay cache path is `./pipeline_output/secure_mesh/replay_cache.json`.

Phase 6 intentionally does not yet execute remote pipeline commands or choose routes automatically. It gives later phases a transport-independent encrypted envelope to carry.

## Phase 7 status

Phase 7 expands discovery beyond normal LAN/Wi-Fi probing:

- `mesh discover` and `mesh paths` can ingest untrusted transport hints from `--hint TYPE=TARGET`, JSON hint files, and config defaults.
- Discovery hints support WireGuard, SSH, Ethernet, hotspot, Bluetooth, serial, radio, and health endpoint targets.
- Appliance discovery records can advertise Bluetooth IDs, serial paths, Ethernet hosts, radio links, hotspot SSIDs, WireGuard endpoints, SSH targets, and public health endpoints.
- `secure_mesh_discovery_hints` can hold inline config hints, and `secure_mesh_discovery_hint_files` can point at JSON hint files.
- Hint files may be a single object, a list of objects, or an object with a `hints` list.
- Discovery hint loading rejects secret-looking fields such as private keys, pairing tokens, PSKs, seeds, and mnemonics.
- A discovered route is trusted only when the presented fingerprint matches a paired, non-revoked registry record.
- Device IDs, device names, hostnames, MAC-like Bluetooth IDs, SSIDs, serial ports, radio labels, and IP addresses remain hints only.

Phase 7 intentionally does not yet select a route and execute commands automatically. It answers: "what routes might exist, and which route hints are backed by paired identity?"

## Phase 8 status

Phase 8 adds optional stronger modes on top of encrypted command envelopes:

- `mesh approval-code` generates a one-time operator approval code for sensitive actions.
- `mesh seal-command --approval-code ... --require-approval` binds the approval proof inside the encrypted body.
- `mesh open-command --approval-code ... --require-approval` verifies the approval proof before returning the decrypted command body.
- Approval proofs are bound to sender, receiver, command, counter, and message ID.
- The approval code itself is never written into the command envelope or command bundle.
- `secure_mesh_require_approval_for_sensitive` can make receivers require approval for configured sensitive actions.
- `secure_mesh_sensitive_actions` defaults to capture start/stop, service start/stop, config updates, mesh key rotation, and mesh revocation.
- `mesh bundle-create` and `mesh bundle-list` support store-and-forward encrypted command bundles for serial, radio, USB/file, or intermittent links.
- Bundle files contain encrypted envelopes and metadata only; command bodies remain inside each envelope's AEAD ciphertext.

Phase 8 intentionally does not yet implement OS hardware-backed key storage. It defines the hooks and optional operator-gated flow first so later hardware-backed keys can protect the same device identities.

## Phase 9 status

Phase 9 connects discovery, route choice, and encrypted command preparation:

- `mesh route-plan` selects the best route for a paired device from registry, config, appliance, operator, and hint-file discovery records.
- Route planning requires trusted fingerprint-backed routes by default.
- `--allow-untrusted-route` exists only for staging and dry-run planning; it does not grant command trust.
- `--transport` can restrict planning to specific carriers such as WireGuard, serial, Bluetooth, radio, SSH, Ethernet, or hotspot.
- `mesh prepare-command` selects a route, writes an encrypted command envelope, and can also write a store-and-forward command bundle tagged with the selected route hint.
- Prepared command summaries include envelope metadata and route metadata, not decrypted command bodies.
- The route planner explains refusal cases such as "only untrusted hints exist" or "no allowed transport exists."

Phase 9 intentionally does not yet send commands over the selected route or execute them on the receiver. It produces the explicit plan and encrypted artifact that a later transport executor can carry.

## Protected assets

The secure mesh must protect:

- Device private keys and per-peer shared secrets.
- Remote capture commands and service-control commands.
- Capture artifacts in transit.
- Capture artifact checksums and provenance metadata.
- Pipeline status messages that could leak device names, interface names, network identifiers, or capture timing.
- Device registry state, including revocation state and permissions.
- Pairing records, fingerprints, counters, and key-rotation history.

The system should treat packet captures themselves as sensitive. Captures can include client MAC addresses, network names, timing, protocol metadata, and payloads.

## Security goals

The secure mesh must provide:

- Mutual authentication between paired devices.
- End-to-end encryption for pipeline commands and artifacts.
- Client-side encryption before data leaves the sending device.
- Replay resistance for commands and artifact-transfer records.
- Tamper detection for commands, status messages, and artifacts.
- Device revocation without re-pairing every other device.
- Permission checks by device role and command type.
- Transport independence so the same trust rules work over Wi-Fi, hotspot, Ethernet, Bluetooth, serial, radio, or store-and-forward files.
- Safe failure: when in doubt, reject the command and keep the capture service closed.

## Non-goals

The secure mesh does not try to provide:

- A brand-new cryptographic primitive.
- Protection against a fully compromised paired device.
- Protection against radio jamming, cable cuts, or denial-of-service flooding.
- Anonymity against a local observer who can see that two radios are transmitting.
- Trust in public discovery responses.
- Secret communication between two devices that have never shared any prior trust material.
- A replacement for OS hardening, least privilege, or remote service sandboxing.

## Roles

The first roles are:

- `controller`: dashboard/CLI operator device that starts captures and pulls artifacts.
- `capture_appliance`: Raspberry Pi or Linux device that runs capture jobs.
- `analyzer`: device allowed to receive captures and run extraction/analysis.
- `observer`: read-only device allowed to see limited status, never capture payloads by default.

Role permissions are allowlists. A new role starts with no permissions.

## Trust boundaries

The following boundaries must be explicit in code and docs:

- Local private key store: trusted only on the device that owns the key.
- Paired-device registry: trusted only after file integrity and revocation checks.
- Discovery network: untrusted.
- Transport link: untrusted until the secure mesh authenticates and encrypts the session.
- Remote capture service: accepts useful commands only from authenticated mesh sessions.
- Dashboard/browser: must not receive private keys, PSKs, passwords, or bearer tokens.
- Logs/reports/artifacts: must not include private keys, PSKs, pairing tokens, or decrypted command bodies unless the operator explicitly exports them.

## Adversary model

Assume an attacker can:

- Sniff all Wi-Fi/hotspot/Bluetooth/radio/Ethernet traffic.
- Replay old packets and old discovery beacons.
- Modify or drop packets.
- Run a fake access point or fake hotspot.
- Run a fake appliance discovery service.
- Try to impersonate a paired device.
- Steal old captures or old command envelopes from disk.
- Guess weak pairing codes.
- Trigger repeated reconnects to look for handshake mistakes.
- Scan the LAN for dashboard, health, and remote-control ports.

Do not assume:

- The local network is private.
- WPA protects pipeline data.
- mDNS/discovery results are truthful.
- Hostnames are stable or trustworthy.
- IP addresses identify devices.
- Bluetooth pairing, hotspot passphrases, or Ethernet cables are enough by themselves.

## Important cryptographic boundary

There is no way for two strangers to have secret encrypted communication before any prior trust exists. A first pairing event must happen through one of these:

- A cable or USB transfer.
- A QR code or short manual verification code.
- An existing SSH trust path.
- A one-time pairing token shown on one device and typed/scanned on the other.

After that first pairing, the devices can send authenticated encrypted traffic immediately on future connections because each side already knows the other side's key material. That is the part that feels similar to a car-key system. We should not copy rolling-code car-key protocols directly; we should use modern, reviewed primitives instead.

## Mandatory rules

Every secure mesh implementation must follow these rules:

- No custom cipher, custom hash, custom MAC, or homemade nonce generator.
- No command execution from discovery traffic.
- No secret material in dashboard HTML, JSON reports, logs, shell history, or release artifacts.
- No trust based only on IP address, hostname, SSID, Bluetooth device name, or MAC address.
- No unauthenticated remote service method that can start, stop, pull, delete, or configure capture jobs.
- No fallback from encrypted mesh mode to cleartext control without an explicit operator warning.
- No accepting an encrypted command without checking sender, receiver, expiry, replay state, authorization, and protocol version.
- No nonce reuse for the same encryption key.
- No long-lived pairing token after a pairing attempt finishes.
- No storing private device keys in `lab.json`.
- No mixing test/demo keys with real paired-device keys.
- No silent downgrade from a newer secure protocol version to an older one.

## Minimum acceptance checks

Phase 1 accepts future implementation work only if it plans tests for:

- Unknown device rejection.
- Revoked device rejection.
- Wrong receiver rejection.
- Expired command rejection.
- Replayed message ID rejection.
- Old counter rejection.
- Tampered ciphertext rejection.
- Tampered associated data rejection.
- Nonce reuse rejection.
- Unauthorized command rejection.
- Missing key rejection.
- Discovery spoof rejection.
- Cleartext fallback warning.
- Secret redaction from logs, dashboard, and reports.

## Custom encryption stance

The project should have custom encryption and decryption at the pipeline layer, but not a custom cipher.

That distinction matters:

- Good custom: our own message envelopes, device registry, key rotation policy, replay windows, command permissions, artifact signing, and pairing UX.
- Bad custom: inventing a new block cipher, stream cipher, hash, MAC, nonce scheme, or unaudited rolling-code algorithm.

The safest version is "custom protocol, standard primitives." That still gives this project a purpose-built security layer that is not just normal Wi-Fi, SSH, or HTTPS, while avoiding the most common cryptographic failure mode: clever math that has not survived public review.

## Primitive suite for the custom layer

The custom pipeline layer should be built from reviewed primitives:

- Identity signatures: Ed25519.
- Key agreement: X25519.
- Message encryption: XChaCha20-Poly1305 or ChaCha20-Poly1305 AEAD.
- Key derivation: HKDF-SHA256 or BLAKE2b-based derivation.
- Replay defense: monotonic counters, message IDs, expiry times, and a sliding replay window.
- Optional second factor: per-peer pre-shared key mixed into session derivation.

This gives us custom encryption/decryption behavior and packet formats without betting the project on a brand-new cipher.

## Recommended default transport

Use WireGuard as the first secure mesh transport, then add the custom pipeline encryption layer inside or alongside it.

WireGuard is a good fit because it:

- Uses static peer public keys, similar to SSH-style key exchange.
- Uses a Noise-based authenticated key exchange.
- Encrypts traffic with modern AEAD primitives.
- Supports roaming between IP addresses.
- Supports an optional pre-shared symmetric key that can act as a second factor mixed into the tunnel handshake.
- Already runs well on Windows, Linux, and Raspberry Pi OS.

For this project, WireGuard should be the default "secure pipe" underneath remote capture and dashboard control. The custom pipeline encryption layer should still exist above it so the same encrypted command envelopes can later move over Bluetooth, serial, radio, hotspot, or store-and-forward links. The existing SSH path can remain as a bootstrap and fallback path.

## Device pairing record

Each paired device should have a local record like this:

```json
{
  "device_id": "raspi-sniffer",
  "role": "capture_appliance",
  "wireguard_public_key": "base64-public-key",
  "pipeline_public_key": "base64-public-key",
  "allowed_tunnel_ip": "10.77.0.2/32",
  "fingerprint": "short-human-checkable-fingerprint",
  "created_at_utc": "2026-04-10T00:00:00Z",
  "last_seen_at_utc": "",
  "revoked": false
}
```

Private keys never go into shared config, docs, logs, reports, or dashboard HTML.

## Discovery

Discovery can be public, but it must not grant trust.

Allowed discovery behavior:

- Broadcast or mDNS announces "a pipeline appliance may be here."
- Discovery payload includes only non-secret fields such as device name, tunnel endpoint, protocol version, and public-key fingerprint.
- The controller treats discovery as a hint only.
- Any command, capture, artifact pull, or status read must happen through the authenticated encrypted mesh.

Disallowed discovery behavior:

- No passwords in beacons.
- No bearer tokens in beacons.
- No cleartext remote control API.
- No trusting a device just because it answered first.

## Pipeline message encryption

WireGuard protects the tunnel, but pipeline messages should still be encrypted and authenticated by the custom pipeline layer so they remain safe if we later add Bluetooth, serial, radio, or store-and-forward transports.

Every command envelope should include:

```json
{
  "protocol": "wifi-pipeline-secure/v1",
  "envelope_type": "secure_mesh_command_envelope_v1",
  "sender_device_id": "controller",
  "receiver_device_id": "raspi-sniffer",
  "message_id": "uuid",
  "counter": 42,
  "created_at_utc": "2026-04-10T00:00:00Z",
  "expires_at_utc": "2026-04-10T00:01:00Z",
  "command": "capture.start",
  "nonce": "base64",
  "ciphertext": "base64",
  "associated_data": "base64",
  "signature": "base64"
}
```

The receiver must reject:

- Unknown devices.
- Revoked devices.
- Expired commands.
- Replayed message IDs or counters.
- Commands not allowed for that device role.
- Unsigned or unauthenticated records.
- Nonces that repeat for the same key.

## Key rotation and car-key-like behavior

The project should support two safe rotation modes:

- Session rotation: the tunnel rotates session keys automatically.
- Pairing-secret rotation: the operator can rotate the WireGuard pre-shared key or pipeline PSK after a successful authenticated session.

For car-key-like one-time behavior, use counters and replay windows on signed encrypted commands. Do not build a custom rolling-code cipher. The goal is "a stolen packet cannot be replayed," not "we invented a new radio crypto system."

## Two-factor model

The strongest practical mode is:

- Factor 1: device private key possession.
- Factor 2: per-peer pre-shared key, operator approval button, QR confirmation, or time-limited pairing code.

That gives us both:

- Persistent paired-device trust for future connections.
- A second gate for pairing, recovery, or sensitive actions.

## Pipeline operations over the mesh

Once paired, the controller should be able to:

- Discover known devices on any transport.
- Run remote doctor/status through the secure mesh.
- Start, stop, and inspect capture jobs.
- Pull captures and verify checksums.
- Push safe config updates.
- Stream progress and artifact metadata.
- Revoke a device immediately.

Remote capture services should bind to the tunnel address by default. If a public health endpoint remains available for discovery, it should reveal only minimal non-sensitive metadata.

## Proposed CLI

```powershell
python .\videopipeline.py mesh init
python .\videopipeline.py mesh pair --host david@raspi-sniffer --interface wlan0
python .\videopipeline.py mesh doctor
python .\videopipeline.py mesh rotate-key --device raspi-sniffer
python .\videopipeline.py mesh discover --hint bluetooth=AA:BB:CC:DD --hint-device raspi-sniffer
python .\videopipeline.py mesh paths --device raspi-sniffer --hints-file .\mesh-hints.json
python .\videopipeline.py mesh route-plan --device raspi-sniffer --transport wireguard
python .\videopipeline.py mesh approval-code
python .\videopipeline.py mesh seal-command --sender controller --receiver raspi-sniffer --command capture.start --counter 1 --out command.envelope.json
python .\videopipeline.py mesh prepare-command --sender controller --receiver raspi-sniffer --command capture.start --counter 2 --out command.envelope.json --bundle-out commands.bundle.json
python .\videopipeline.py mesh open-command --receiver raspi-sniffer --envelope command.envelope.json --json
python .\videopipeline.py mesh bundle-create --envelope command.envelope.json --out commands.bundle.json --route-hint serial:COM4
python .\videopipeline.py mesh bundle-list --bundle commands.bundle.json
python .\videopipeline.py mesh revoke --device raspi-sniffer
python .\videopipeline.py start-remote --secure-mesh --device raspi-sniffer --duration 60 --run all
```

## Implementation phases

Phase 1 is this threat model and ruleset:

- Define protected assets, security goals, and non-goals.
- Define roles, trust boundaries, and adversary capabilities.
- Define mandatory rules and acceptance checks.
- Block future mesh code that violates the cryptographic boundary.

Phase 2 should add the local secure mesh foundation:

- Add secure mesh config defaults.
- Add a paired-device registry.
- Add device IDs, roles, permissions, fingerprints, and revocation state.
- Keep private keys outside `lab.json`.
- Add tests for registry save/load, revocation, permissions, and secret redaction.

Phase 3 adds pairing and key generation:

- Generate controller and Pi identity keys.
- Generate optional per-peer pre-shared keys.
- Support SSH, cable/file, QR/manual-code, or one-time token pairing.
- Show human-checkable fingerprints.
- Reject weak or expired pairing tokens.

Phase 4 adds automatic discovery and route inventory:

- Scan paired registry transport hints.
- Include saved `remote_host` / `remote_path` config hints.
- Probe appliance health endpoints for SSH, health, WireGuard, and hotspot hints.
- Match discovered fingerprints against the paired registry.
- Mark device-name/IP/SSID matches as untrusted hints unless a fingerprint matches.
- Rank candidate routes by trust and transport strength.

Phase 5 adds WireGuard for the first secure transport:

- Generate controller and Pi WireGuard keys.
- Generate optional per-peer pre-shared keys.
- Install WireGuard config on the Pi.
- Save only public peer metadata in project config.
- Bind remote control and capture APIs to the tunnel IP.
- Add `mesh doctor` to confirm tunnel reachability and key fingerprints.

Phase 6 adds custom pipeline command encryption:

- Device IDs and role-based permissions.
- Signed/encrypted command records.
- X25519 session setup between already-paired device identities.
- AEAD encrypted command and artifact envelopes.
- Replay protection and command expiry.
- Artifact checksum verification tied to message IDs.

Phase 7 extends transport-independent discovery:

- LAN/hotspot discovery.
- Optional Bluetooth or serial discovery adapters.
- Discovery as hints only, with all control over the secure mesh.

Phase 8 adds stronger optional modes:

- Hardware-backed keys where available.
- Manual approval for sensitive commands.
- Periodic PSK rotation.
- Store-and-forward encrypted command bundles for intermittent links.

Phase 9 adds route planning and prepared command artifacts:

- Select the best trusted route from discovery records.
- Refuse untrusted or revoked routes by default.
- Prepare encrypted command envelopes and optional bundles for the selected carrier.
- Keep remote execution explicit and separate from planning.

## Sources

- [WireGuard Protocol & Cryptography](https://www.wireguard.com/protocol/)
- [WireGuard overview and cryptokey routing](https://www.wireguard.com/)
- [WireGuard known limitations](https://www.wireguard.com/known-limitations/)
- [Noise Protocol Framework specification](https://noiseprotocol.org/noise_rev34.html)
- [libsodium public-key authenticated encryption](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)
