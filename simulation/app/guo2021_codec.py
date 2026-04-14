#!/usr/bin/env python3
"""JSON helpers for shipping Guo2021 messages over UDP."""

from __future__ import annotations

import json
from typing import Any, Dict, Tuple

from guo2021 import (
    MessageM1,
    MessageM2,
    MessageM3,
    MessageM4,
    MessageM5,
    MessageM6,
    MessageM8,
    MessageM9,
    MessageM10,
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


def m1_to_dict(message: MessageM1) -> Dict[str, Any]:
    return {
        "tid": message.tid,
        "sat_id": message.satellite_id,
        "gs_id": message.ground_id,
        "pk_i": message.pk_i_bytes.hex(),
        "alpha_i": _int_to_hex(message.alpha_i),
        "t1": int(message.T1),
    }


def dict_to_m1(payload: Dict[str, Any]) -> MessageM1:
    return MessageM1(
        tid=payload["tid"],
        satellite_id=payload["sat_id"],
        ground_id=payload["gs_id"],
        pk_i_bytes=bytes.fromhex(payload["pk_i"]),
        alpha_i=_hex_to_int(payload["alpha_i"]),
        T1=int(payload["t1"]),
    )


def m2_to_dict(message: MessageM2) -> Dict[str, Any]:
    return {
        "tid": message.tid,
        "sat_id": message.satellite_id,
        "gs_id": message.ground_id,
        "pk_i": message.pk_i_bytes.hex(),
        "pk_j": message.pk_j_bytes.hex(),
        "alpha_j": _int_to_hex(message.alpha_j),
        "t1": int(message.T1),
        "t2": int(message.T2),
    }


def dict_to_m2(payload: Dict[str, Any]) -> MessageM2:
    return MessageM2(
        tid=payload["tid"],
        satellite_id=payload["sat_id"],
        ground_id=payload["gs_id"],
        pk_i_bytes=bytes.fromhex(payload["pk_i"]),
        pk_j_bytes=bytes.fromhex(payload["pk_j"]),
        alpha_j=_hex_to_int(payload["alpha_j"]),
        T1=int(payload["t1"]),
        T2=int(payload["t2"]),
    )


def m3_to_dict(message: MessageM3, *, metrics: Dict[str, Any] | None = None) -> Dict[str, Any]:
    payload = {
        "tid": message.tid,
        "sat_id": message.satellite_id,
        "gs_id": message.ground_id,
        "pk_i": message.pk_i_bytes.hex(),
        "pk_j": message.pk_j_bytes.hex(),
        "pk_k": message.pk_k_bytes.hex(),
        "alpha_k": _int_to_hex(message.alpha_k),
        "alpha_k1": _int_to_hex(message.alpha_k1),
        "t1": int(message.T1),
        "t2": int(message.T2),
        "t3": int(message.T3),
    }
    if metrics:
        payload["metrics"] = metrics
    return payload


def dict_to_m3(payload: Dict[str, Any]) -> Tuple[MessageM3, Dict[str, Any]]:
    metrics = payload.get("metrics", {})
    message = MessageM3(
        tid=payload["tid"],
        satellite_id=payload["sat_id"],
        ground_id=payload["gs_id"],
        pk_i_bytes=bytes.fromhex(payload["pk_i"]),
        pk_j_bytes=bytes.fromhex(payload["pk_j"]),
        pk_k_bytes=bytes.fromhex(payload["pk_k"]),
        alpha_k=_hex_to_int(payload["alpha_k"]),
        alpha_k1=_hex_to_int(payload["alpha_k1"]),
        T1=int(payload["t1"]),
        T2=int(payload["t2"]),
        T3=int(payload["t3"]),
    )
    return message, metrics if isinstance(metrics, dict) else {}


def m4_to_dict(message: MessageM4, *, metrics: Dict[str, Any] | None = None) -> Dict[str, Any]:
    payload = {
        "tid": message.tid,
        "sat_id": message.satellite_id,
        "gs_id": message.ground_id,
        "pk_j": message.pk_j_bytes.hex(),
        "pk_k": message.pk_k_bytes.hex(),
        "alpha_j1": _int_to_hex(message.alpha_j1),
        "t4": int(message.T4),
    }
    if metrics:
        payload["metrics"] = metrics
    return payload


def dict_to_m4(payload: Dict[str, Any]) -> Tuple[MessageM4, Dict[str, Any]]:
    metrics = payload.get("metrics", {})
    message = MessageM4(
        tid=payload["tid"],
        satellite_id=payload["sat_id"],
        ground_id=payload["gs_id"],
        pk_j_bytes=bytes.fromhex(payload["pk_j"]),
        pk_k_bytes=bytes.fromhex(payload["pk_k"]),
        alpha_j1=_hex_to_int(payload["alpha_j1"]),
        T4=int(payload["t4"]),
    )
    return message, metrics if isinstance(metrics, dict) else {}


def m5_to_dict(message: MessageM5) -> Dict[str, Any]:
    return {
        "tid": message.tid,
        "sat_id": message.satellite_id,
        "pk_i1": message.pk_i1_bytes.hex(),
        "alpha_i1": _int_to_hex(message.alpha_i1),
        "t5": int(message.T5),
    }


def dict_to_m5(payload: Dict[str, Any]) -> MessageM5:
    return MessageM5(
        tid=payload["tid"],
        satellite_id=payload["sat_id"],
        pk_i1_bytes=bytes.fromhex(payload["pk_i1"]),
        alpha_i1=_hex_to_int(payload["alpha_i1"]),
        T5=int(payload["t5"]),
    )


def m6_to_dict(message: MessageM6) -> Dict[str, Any]:
    return {
        "tid": message.tid,
        "sat_id": message.satellite_id,
        "pk_n": message.pk_n_bytes.hex(),
        "alpha_n": _int_to_hex(message.alpha_n),
        "t6": int(message.T6),
    }


def dict_to_m6(payload: Dict[str, Any]) -> MessageM6:
    return MessageM6(
        tid=payload["tid"],
        satellite_id=payload["sat_id"],
        pk_n_bytes=bytes.fromhex(payload["pk_n"]),
        alpha_n=_hex_to_int(payload["alpha_n"]),
        T6=int(payload["t6"]),
    )


def m8_to_dict(message: MessageM8) -> Dict[str, Any]:
    return {
        "source_gs": message.source_gs,
        "target_gs": message.target_gs,
        "tid_list": message.tid_list,
        "pk_i2_list": [item.hex() for item in message.pk_i2_list],
        "pk_k1": message.pk_k1_bytes.hex(),
        "alpha_k1": _int_to_hex(message.alpha_k1),
        "t7": int(message.T7),
    }


def dict_to_m8(payload: Dict[str, Any]) -> MessageM8:
    return MessageM8(
        source_gs=payload["source_gs"],
        target_gs=payload["target_gs"],
        tid_list=list(payload["tid_list"]),
        pk_i2_list=[bytes.fromhex(item) for item in payload["pk_i2_list"]],
        pk_k1_bytes=bytes.fromhex(payload["pk_k1"]),
        alpha_k1=_hex_to_int(payload["alpha_k1"]),
        T7=int(payload["t7"]),
    )


def m9_to_dict(message: MessageM9) -> Dict[str, Any]:
    return {
        "source_gs": message.source_gs,
        "target_gs": message.target_gs,
        "pk_t": message.pk_t_bytes.hex(),
        "alpha_t1": _int_to_hex(message.alpha_t1),
        "t8": int(message.T8),
    }


def dict_to_m9(payload: Dict[str, Any]) -> MessageM9:
    return MessageM9(
        source_gs=payload["source_gs"],
        target_gs=payload["target_gs"],
        pk_t_bytes=bytes.fromhex(payload["pk_t"]),
        alpha_t1=_hex_to_int(payload["alpha_t1"]),
        T8=int(payload["t8"]),
    )


def m10_to_dict(message: MessageM10) -> Dict[str, Any]:
    return {
        "tid": message.tid,
        "nonce": message.nonce.hex(),
        "ciphertext": message.ciphertext.hex(),
    }


def dict_to_m10(payload: Dict[str, Any]) -> MessageM10:
    return MessageM10(
        tid=payload["tid"],
        nonce=bytes.fromhex(payload["nonce"]),
        ciphertext=bytes.fromhex(payload["ciphertext"]),
    )
