#!/usr/bin/env python3
"""JSON helpers for Yang2024 vehicular handover simulation messages."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable

PROTOCOLS_PATH = Path(__file__).resolve().parents[2] / "protocols"
if str(PROTOCOLS_PATH) not in sys.path:
    sys.path.insert(0, str(PROTOCOLS_PATH))

import yang2024


def _pseudo_id_to_dict(pseudo_id: yang2024.PseudoIdentity) -> Dict[str, Any]:
    return {
        "component1": pseudo_id.component1.hex(),
        "component2": pseudo_id.component2.hex(),
        "expiry_ts": pseudo_id.expiry_ts,
    }


def _pseudo_id_from_dict(data: Dict[str, Any]) -> yang2024.PseudoIdentity:
    return yang2024.PseudoIdentity(
        component1=bytes.fromhex(data["component1"]),
        component2=bytes.fromhex(data["component2"]),
        expiry_ts=int(data["expiry_ts"]),
    )


def _public_key_to_dict(public_key: yang2024.VehiclePublicKey) -> Dict[str, Any]:
    return {
        "B_i": public_key.B_i.hex(),
        "R_i": public_key.R_i.hex(),
    }


def _public_key_from_dict(data: Dict[str, Any]) -> yang2024.VehiclePublicKey:
    return yang2024.VehiclePublicKey(
        B_i=bytes.fromhex(data["B_i"]),
        R_i=bytes.fromhex(data["R_i"]),
    )


def _signature_to_dict(signature: yang2024.Signature) -> Dict[str, Any]:
    return {
        "U_i": signature.U_i.hex(),
        "delta_i": str(int(signature.delta_i)),
    }


def _signature_from_dict(data: Dict[str, Any]) -> yang2024.Signature:
    return yang2024.Signature(
        U_i=bytes.fromhex(data["U_i"]),
        delta_i=int(data["delta_i"]),
    )


def broadcast_to_dict(broadcast: yang2024.SignedBroadcast) -> Dict[str, Any]:
    return {
        "message": broadcast.message.hex(),
        "timestamp": broadcast.timestamp,
        "pseudo_id": _pseudo_id_to_dict(broadcast.pseudo_id),
        "public_key": _public_key_to_dict(broadcast.public_key),
        "signature": _signature_to_dict(broadcast.signature),
    }


def broadcast_from_dict(data: Dict[str, Any]) -> yang2024.SignedBroadcast:
    return yang2024.SignedBroadcast(
        pseudo_id=_pseudo_id_from_dict(data["pseudo_id"]),
        public_key=_public_key_from_dict(data["public_key"]),
        message=bytes.fromhex(data["message"]),
        timestamp=int(data["timestamp"]),
        signature=_signature_from_dict(data["signature"]),
    )


def aggregate_to_dict(aggregate: yang2024.AggregateSignature) -> Dict[str, Any]:
    return {
        "aggregate_point": aggregate.aggregate_point.hex(),
        "delta": str(int(aggregate.delta)),
        "count": aggregate.signature_count,
    }


def aggregate_from_dict(data: Dict[str, Any]) -> yang2024.AggregateSignature:
    return yang2024.AggregateSignature(
        aggregate_point=bytes.fromhex(data["aggregate_point"]),
        delta=int(data["delta"]),
        signature_count=int(data["count"]),
    )


def encode_payload(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode_payload(data: bytes) -> Dict[str, Any]:
    payload = json.loads(data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("invalid payload")
    return payload


def encode_switch_request(ue_id: str, target_rsu: str, broadcast: yang2024.SignedBroadcast) -> bytes:
    payload = {
        "type": "switch_request",
        "ue_id": ue_id,
        "target_rsu": target_rsu,
        "broadcast": broadcast_to_dict(broadcast),
    }
    return encode_payload(payload)


def encode_switch_response(payload: Dict[str, Any]) -> bytes:
    response = {"type": "switch_response"}
    response.update(payload)
    return encode_payload(response)


def encode_aggregate_request(
    *,
    rsu_id: str,
    broadcasts: Iterable[yang2024.SignedBroadcast],
    aggregate: yang2024.AggregateSignature,
) -> bytes:
    payload = {
        "type": "aggregate_verify",
        "rsu_id": rsu_id,
        "broadcasts": [broadcast_to_dict(item) for item in broadcasts],
        "aggregate": aggregate_to_dict(aggregate),
    }
    return encode_payload(payload)


def encode_aggregate_response(payload: Dict[str, Any]) -> bytes:
    response = {"type": "aggregate_response"}
    response.update(payload)
    return encode_payload(response)


def ensure_type(payload: Dict[str, Any], expected: str) -> Dict[str, Any]:
    if payload.get("type") != expected:
        raise ValueError(f"unexpected payload type {payload.get('type')!r}")
    return payload
