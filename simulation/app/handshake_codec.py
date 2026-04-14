#!/usr/bin/env python3
"""JSON helpers for shipping SSINAuth handshake messages over UDP."""

from __future__ import annotations

import json
from typing import Any, Dict

from ssinauth import SecureEnvelope, UplinkRequest


def encode_uplink(ue_id: str, uplink: UplinkRequest) -> bytes:
    payload = {
        "type": "uplink",
        "ue_id": ue_id,
        "ts5": uplink.TS5,
        "q_i": uplink.Q_bytes.hex(),
        "v1": uplink.V1.hex(),
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode_uplink(data: bytes) -> Dict[str, Any]:
    payload = json.loads(data.decode("utf-8"))
    if payload.get("type") != "uplink":
        raise ValueError("invalid uplink payload type")
    return payload


def encode_success_response(
    ue_id: str,
    ts6: int,
    q_b: bytes,
    v2: bytes,
    cpu_ms: float,
    processing_ms: float,
) -> bytes:
    payload = {
        "type": "downlink",
        "status": "ok",
        "ue_id": ue_id,
        "ts6": ts6,
        "q_b": q_b.hex(),
        "v2": v2.hex(),
        "cpu_ms": cpu_ms,
        "processing_ms": processing_ms,
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def encode_error_response(ue_id: str, failed_stage: str, message: str) -> bytes:
    payload = {
        "type": "downlink",
        "status": "error",
        "ue_id": ue_id,
        "failed_stage": failed_stage,
        "message": message,
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode_response(data: bytes) -> Dict[str, Any]:
    payload = json.loads(data.decode("utf-8"))
    if payload.get("type") != "downlink":
        raise ValueError("invalid downlink payload type")
    return payload


def encode_secure_message(msg_type: str, ue_id: str, envelope: SecureEnvelope, **extra: Any) -> bytes:
    payload = {
        "type": msg_type,
        "ue_id": ue_id,
        "channel_label": envelope.channel_label,
        "nonce": envelope.nonce.hex(),
        "ciphertext": envelope.ciphertext.hex(),
    }
    payload.update({k: v for k, v in extra.items() if v is not None})
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode_secure_message(data: bytes) -> Dict[str, Any]:
    payload = json.loads(data.decode("utf-8"))
    if "type" not in payload or "nonce" not in payload or "ciphertext" not in payload:
        raise ValueError("invalid secure payload")
    return payload


def envelope_from_payload(payload: Dict[str, Any]) -> SecureEnvelope:
    return SecureEnvelope(
        channel_label=payload["channel_label"],
        nonce=bytes.fromhex(payload["nonce"]),
        ciphertext=bytes.fromhex(payload["ciphertext"]),
    )
