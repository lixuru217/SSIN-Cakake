#!/usr/bin/env python3
"""JSON helpers for shipping Liu2022 messages over UDP."""

from __future__ import annotations

import json
from typing import Any, Dict

from liu2022 import (
    AccessRequest,
    AccessResponse,
    GroupCredential,
    GroupRequest,
    GroupResponse,
    HandoverRequest,
    HandoverResponse,
    LKATicket,
    MaskedIdentity,
)


def _int_to_hex(value: int) -> str:
    return format(value, "x")


def _hex_to_int(value: str) -> int:
    return int(value, 16)


def encode_envelope(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode_envelope(data: bytes) -> Dict[str, Any]:
    payload = json.loads(data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("invalid payload format")
    return payload


def masked_identity_to_dict(identity: MaskedIdentity) -> Dict[str, Any]:
    return {
        "p_id": identity.p_id.hex(),
        "index_id": int(identity.index_id),
        "p_pk": identity.p_pk.hex(),
        "index_pk": int(identity.index_pk),
    }


def dict_to_masked_identity(payload: Dict[str, Any]) -> MaskedIdentity:
    return MaskedIdentity(
        p_id=bytes.fromhex(payload["p_id"]),
        index_id=int(payload["index_id"]),
        p_pk=bytes.fromhex(payload["p_pk"]),
        index_pk=int(payload["index_pk"]),
    )


def group_request_to_dict(message: GroupRequest) -> Dict[str, Any]:
    return {
        "type": "group_request",
        "ap_id": message.ap_id,
        "ts1": int(message.ts1),
        "pk_gpi": message.pk_gpi_bytes.hex(),
        "pk_ap": message.pk_ap_bytes.hex(),
        "v_gpi": _int_to_hex(message.v_gpi),
    }


def dict_to_group_request(payload: Dict[str, Any]) -> GroupRequest:
    return GroupRequest(
        ap_id=payload["ap_id"],
        ts1=int(payload["ts1"]),
        pk_gpi_bytes=bytes.fromhex(payload["pk_gpi"]),
        pk_ap_bytes=bytes.fromhex(payload["pk_ap"]),
        v_gpi=_hex_to_int(payload["v_gpi"]),
    )


def group_credential_to_dict(credential: GroupCredential) -> Dict[str, Any]:
    return {
        "apgid": credential.target_apgid,
        "sgk": credential.sgk_bytes.hex(),
        "expiry": int(credential.expiry_ts),
    }


def dict_to_group_credential(payload: Dict[str, Any]) -> GroupCredential:
    return GroupCredential(
        target_apgid=payload["apgid"],
        sgk_bytes=bytes.fromhex(payload["sgk"]),
        expiry_ts=int(payload["expiry"]),
    )


def group_response_to_dict(message: GroupResponse) -> Dict[str, Any]:
    return {
        "type": "group_response",
        "apgid": message.apgid,
        "hac": [group_credential_to_dict(item) for item in message.hac],
        "coefficients": [_int_to_hex(value) for value in message.coefficients],
        "ts1_gm": int(message.ts1_gm),
        "pk_g": message.pk_g_bytes.hex(),
        "gm_id": message.gm_id,
        "pkgm": message.pkgm_bytes.hex(),
        "v_gm": _int_to_hex(message.v_gm),
    }


def dict_to_group_response(payload: Dict[str, Any]) -> GroupResponse:
    return GroupResponse(
        apgid=payload["apgid"],
        hac=[dict_to_group_credential(item) for item in payload.get("hac", [])],
        coefficients=[_hex_to_int(item) for item in payload.get("coefficients", [])],
        ts1_gm=int(payload["ts1_gm"]),
        pk_g_bytes=bytes.fromhex(payload["pk_g"]),
        gm_id=payload["gm_id"],
        pkgm_bytes=bytes.fromhex(payload["pkgm"]),
        v_gm=_hex_to_int(payload["v_gm"]),
    )


def lka_ticket_to_dict(ticket: LKATicket) -> Dict[str, Any]:
    return {
        "apgid": ticket.apgid,
        "nonce": ticket.nonce.hex(),
        "ciphertext": ticket.encrypted_payload.hex(),
        "expiry": int(ticket.expiry_ts),
    }


def dict_to_lka_ticket(payload: Dict[str, Any]) -> LKATicket:
    return LKATicket(
        apgid=payload["apgid"],
        nonce=bytes.fromhex(payload["nonce"]),
        encrypted_payload=bytes.fromhex(payload["ciphertext"]),
        expiry_ts=int(payload["expiry"]),
    )


def access_request_to_dict(message: AccessRequest) -> Dict[str, Any]:
    payload = {
        "type": "access_request",
        "identity": masked_identity_to_dict(message.identity),
        "ts1": int(message.ts1),
        "pk_ue_ep": message.pk_ue_ep_bytes.hex(),
        "v_ue": _int_to_hex(message.v_ue),
    }
    return payload


def dict_to_access_request(payload: Dict[str, Any]) -> AccessRequest:
    identity_payload = payload["identity"]
    return AccessRequest(
        identity=dict_to_masked_identity(identity_payload),
        ts1=int(payload["ts1"]),
        pk_ue_ep_bytes=bytes.fromhex(payload["pk_ue_ep"]),
        v_ue=_hex_to_int(payload["v_ue"]),
    )


def access_response_to_dict(message: AccessResponse) -> Dict[str, Any]:
    return {
        "type": "access_response",
        "nonce": message.nonce.hex(),
        "ciphertext": message.ciphertext.hex(),
        "lka": [lka_ticket_to_dict(item) for item in message.lka],
        "ts2": int(message.ts2),
        "pk_ap_ep": message.pk_ap_ep_bytes.hex(),
        "ap_id": message.ap_id,
        "pk_ap": message.pk_ap_bytes.hex(),
        "v_ap": _int_to_hex(message.v_ap),
    }


def dict_to_access_response(payload: Dict[str, Any]) -> AccessResponse:
    return AccessResponse(
        ciphertext=bytes.fromhex(payload["ciphertext"]),
        nonce=bytes.fromhex(payload["nonce"]),
        lka=[dict_to_lka_ticket(item) for item in payload.get("lka", [])],
        ts2=int(payload["ts2"]),
        pk_ap_ep_bytes=bytes.fromhex(payload["pk_ap_ep"]),
        ap_id=payload["ap_id"],
        pk_ap_bytes=bytes.fromhex(payload["pk_ap"]),
        v_ap=_hex_to_int(payload["v_ap"]),
    )


def handover_request_to_dict(message: HandoverRequest) -> Dict[str, Any]:
    return {
        "type": "handover_request",
        "p_id": message.p_id.hex(),
        "index_id": int(message.index_id),
        "ru": message.ru.hex(),
        "ts1": int(message.ts1),
        "target_ap": message.target_ap_id,
        "lka": [lka_ticket_to_dict(item) for item in message.lka],
        "v_ue": message.v_ue.hex(),
    }


def dict_to_handover_request(payload: Dict[str, Any]) -> HandoverRequest:
    return HandoverRequest(
        p_id=bytes.fromhex(payload["p_id"]),
        index_id=int(payload["index_id"]),
        ru=bytes.fromhex(payload["ru"]),
        ts1=int(payload["ts1"]),
        target_ap_id=payload["target_ap"],
        lka=[dict_to_lka_ticket(item) for item in payload.get("lka", [])],
        v_ue=bytes.fromhex(payload["v_ue"]),
    )


def handover_response_to_dict(message: HandoverResponse) -> Dict[str, Any]:
    return {
        "type": "handover_response",
        "r_ap": message.r_ap.hex(),
        "ts2": int(message.ts2),
        "ciphertext": message.ciphertext.hex(),
        "nonce": message.nonce.hex(),
        "ap_id": message.ap_id,
        "v_ap": message.v_ap.hex(),
        "lka": [lka_ticket_to_dict(item) for item in message.lka],
    }


def dict_to_handover_response(payload: Dict[str, Any]) -> HandoverResponse:
    return HandoverResponse(
        r_ap=bytes.fromhex(payload["r_ap"]),
        ts2=int(payload["ts2"]),
        ciphertext=bytes.fromhex(payload["ciphertext"]),
        nonce=bytes.fromhex(payload["nonce"]),
        ap_id=payload["ap_id"],
        v_ap=bytes.fromhex(payload["v_ap"]),
        lka=[dict_to_lka_ticket(item) for item in payload.get("lka", [])],
    )
