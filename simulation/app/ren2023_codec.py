#!/usr/bin/env python3
"""Encoding helpers for REN2023 handover messages."""

from __future__ import annotations

import base64
import json
from dataclasses import asdict
from typing import Any, Dict

PROTOCOLS_PATH = __import__("pathlib").Path(__file__).resolve().parents[2] / "protocols"
import sys

if str(PROTOCOLS_PATH) not in sys.path:
    sys.path.insert(0, str(PROTOCOLS_PATH))

import ren2023


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def encode_json(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode_json(data: bytes) -> Dict[str, Any]:
    return json.loads(data.decode("utf-8"))


def handover_request_to_dict(request: ren2023.TerminalHandoverRequest, *, ue_id: str) -> Dict[str, Any]:
    return {
        "type": "handover_request",
        "pid": request.pid,
        "ue_id": ue_id,
    }


def handover_request_from_dict(payload: Dict[str, Any]) -> ren2023.TerminalHandoverRequest:
    return ren2023.TerminalHandoverRequest(pid=str(payload["pid"]))


def handover_uplink_to_dict(uplink: ren2023.UAVHandoverUplink) -> Dict[str, Any]:
    return {
        "type": "handover_uplink",
        "pid": uplink.pid,
        "nu": _b64(uplink.nu),
        "uav_id": uplink.uav_id,
    }


def handover_uplink_from_dict(payload: Dict[str, Any]) -> ren2023.UAVHandoverUplink:
    return ren2023.UAVHandoverUplink(
        pid=str(payload["pid"]),
        nu=_b64d(payload["nu"]),
        uav_id=str(payload["uav_id"]),
    )


def ho_response_to_dict(response: ren2023.NCCUAVHOResponse) -> Dict[str, Any]:
    return {
        "type": "handover_response",
        "cid_nu": _b64(response.cid_nu),
        "pid_masked": _b64(response.pid_masked),
        "sk_tnu": _b64(response.sk_tnu),
        "auth_nu_t": _b64(response.auth_nu_t),
    }


def ho_response_from_dict(payload: Dict[str, Any]) -> ren2023.NCCUAVHOResponse:
    return ren2023.NCCUAVHOResponse(
        cid_nu=_b64d(payload["cid_nu"]),
        pid_masked=_b64d(payload["pid_masked"]),
        sk_tnu=_b64d(payload["sk_tnu"]),
        auth_nu_t=_b64d(payload["auth_nu_t"]),
    )


def ho_downlink_to_dict(message: ren2023.UAVTerHOResponse) -> Dict[str, Any]:
    return {
        "type": "handover_downlink",
        "nu": _b64(message.nu),
        "cid_nu": _b64(message.cid_nu),
        "pid_masked": _b64(message.pid_masked),
        "sk_tnu": _b64(message.sk_tnu),
        "auth_nu_t": _b64(message.auth_nu_t),
    }


def ho_downlink_from_dict(payload: Dict[str, Any]) -> ren2023.UAVTerHOResponse:
    return ren2023.UAVTerHOResponse(
        nu=_b64d(payload["nu"]),
        cid_nu=_b64d(payload["cid_nu"]),
        pid_masked=_b64d(payload["pid_masked"]),
        sk_tnu=_b64d(payload["sk_tnu"]),
        auth_nu_t=_b64d(payload["auth_nu_t"]),
    )


def terminal_response_to_dict(pid: str, response: ren2023.TerminalHandoverResponse) -> Dict[str, Any]:
    return {
        "type": "handover_terminal_response",
        "pid": pid,
        "n_t": _b64(response.n_t),
        "auth_tnu": _b64(response.auth_tnu),
        "r_masked": _b64(response.r_masked),
    }


def terminal_response_from_dict(payload: Dict[str, Any]) -> ren2023.TerminalHandoverResponse:
    return ren2023.TerminalHandoverResponse(
        n_t=_b64d(payload["n_t"]),
        auth_tnu=_b64d(payload["auth_tnu"]),
        r_masked=_b64d(payload["r_masked"]),
    )


def stored_payload_to_dict(payload: ren2023._StoredHandoverPayload) -> Dict[str, Any]:  # type: ignore[attr-defined]
    return {
        "terminal_id": payload.terminal_id,
        "uav_id": payload.uav_id,
        "pid_new": payload.pid_new,
        "challenge_new": _b64(payload.challenge_new),
        "response_new": _b64(payload.response_new),
        "sk_tnu": _b64(payload.sk_tnu),
    }


def stored_payload_from_dict(data: Dict[str, Any]) -> ren2023._StoredHandoverPayload:  # type: ignore[attr-defined]
    return ren2023._StoredHandoverPayload(  # type: ignore[attr-defined]
        terminal_id=str(data["terminal_id"]),
        uav_id=str(data["uav_id"]),
        pid_new=str(data["pid_new"]),
        challenge_new=_b64d(data["challenge_new"]),
        response_new=_b64d(data["response_new"]),
        sk_tnu=_b64d(data["sk_tnu"]),
    )
