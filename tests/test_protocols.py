from __future__ import annotations

from wifi_pipeline import protocols


def test_shannon_entropy_zero() -> None:
    assert protocols.shannon_entropy(b"") == 0.0
    assert protocols.shannon_entropy(b"\x00" * 64) == 0.0


def test_shannon_entropy_nonzero() -> None:
    value = protocols.shannon_entropy(b"\x00\x01" * 64)
    assert value > 0.0


def test_parse_rtp_header_valid() -> None:
    payload = bytes(
        [
            0x80, 0x60, 0x00, 0x01,  # V=2, PT=96, seq=1
            0x00, 0x00, 0x00, 0x2a,  # timestamp=42
            0xde, 0xad, 0xbe, 0xef,  # ssrc
        ]
    ) + b"DATA"
    header = protocols.parse_rtp_header(payload)
    assert header is not None
    assert header.payload_type == 96
    assert header.sequence == 1
    assert header.timestamp == 42
    assert header.ssrc == 0xDEADBEEF


def test_strip_rtp_header_returns_payload() -> None:
    payload = bytes(
        [
            0x80, 0x60, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x10,
            0x00, 0x00, 0x00, 0x01,
        ]
    ) + b"PAYLOAD"
    stripped, header = protocols.strip_rtp_header(payload)
    assert header is not None
    assert stripped == b"PAYLOAD"


def test_mpegts_detection_and_split() -> None:
    packet = b"\x47" + b"\x00" * 187
    data = packet * 3
    assert protocols.looks_like_mpegts(data)
    packets = protocols.split_mpegts_packets(data)
    assert len(packets) == 3


def test_magic_lookups() -> None:
    assert protocols.looks_like_png(b"\x89PNG\r\n\x1a\nxxxx")
    assert protocols.looks_like_gif(b"GIF89a1234")
    assert protocols.looks_like_bmp(b"BMxxxx")
    assert protocols.looks_like_wav(b"RIFFxxxxWAVE")
    assert protocols.looks_like_ogg(b"OggSxxxx")
    assert protocols.looks_like_flac(b"fLaCxxxx")
    assert protocols.looks_like_zip(b"PK\x03\x04xxxx")
    assert protocols.looks_like_gzip(b"\x1f\x8bxxxx")


def test_guess_unit_type_and_mappings() -> None:
    assert protocols.guess_unit_type(b'{"hello":"world"}') == "json_text"
    assert protocols.guess_unit_type(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n") == "http_text"
    assert protocols.payload_family("png_image") == "image"
    assert protocols.suggested_extension("plain_text") == ".txt"


def test_nal_detection_prefers_real_h264_over_text_like_false_positives() -> None:
    h264_sample = (
        b"\x00\x00\x00\x01\x67\x64\x00\x1f\xac\xd9\x40\x78"
        b"\x00\x00\x00\x01\x68\xee\x3c\x80"
        b"\x00\x00\x00\x01\x65\x88\x84\x21\xa0"
    )
    nals, codec = protocols.split_nal_units(h264_sample)

    assert codec == "h264"
    assert len(nals) == 3
    assert protocols.guess_unit_type(h264_sample) == "h264_nal"

    ssh_like = (
        b"\x00" * 55
        + b"\x00\x00\x01\x0ecurve25519-sha256,curve25519-sha256@libssh.org"
        + b"\x00" * 64
        + b"\x00\x00\x01\xcfssh-ed25519-cert-v01@openssh.com,ssh-ed25519"
    )
    false_nals, false_codec = protocols.split_nal_units(ssh_like)

    assert false_nals == []
    assert false_codec is None
    assert protocols.guess_unit_type(ssh_like) == "opaque_chunk"


def test_protocol_support_profiles_and_stream_summary() -> None:
    png = protocols.protocol_support("png_image")
    opaque = protocols.protocol_support("opaque_chunk")
    summary = protocols.summarize_stream_support({"png_image": 3, "opaque_chunk": 1})

    assert png.decode_level == "guaranteed"
    assert png.replay_level == "guaranteed"
    assert opaque.replay_level == "unsupported"
    assert summary["dominant_unit_type"] == "png_image"
    assert summary["replay_hint"] == "png"
    assert summary["replay_level"] == "unsupported"


def test_summarize_protocol_hits_counts_multiple_types() -> None:
    summary = protocols.summarize_protocol_hits(
        [
            b"\x89PNG\r\n\x1a\npayload",
            b'{"hello":"world"}',
            b"\x01\x02\x03",
        ]
    )

    assert summary["png"] == 1
    assert summary["json"] == 1
    assert summary["opaque"] == 1
