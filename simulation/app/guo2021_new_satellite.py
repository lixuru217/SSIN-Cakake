#!/usr/bin/env python3
"""New satellite authenticator (L_n) for Guo2021 satellite switching."""

from __future__ import annotations

import argparse
import logging
import socket
import time
from pathlib import Path

from metrics import Timer, sample_cpu

from guo2021 import MessageM5, MessageM6, SatelliteState, hash_d7, point_from_bytes, point_add, generator
from guo2021_codec import decode_envelope, dict_to_m5, encode_envelope, m6_to_dict
from guo2021_context import get_identifiers, get_new_satellite_state, load_context
from guo2021 import random_scalar, point_to_bytes

from guo2021 import hash_d6, normalize_scalar

logger = logging.getLogger("guo2021_new_sat")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Guo2021 new satellite authenticator (L_n)")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=5000, help="UDP port")
    parser.add_argument("--old-host", default="leo1", help="Old satellite host")
    parser.add_argument("--old-port", type=int, default=6000, help="Old satellite UDP port")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--tolerance", type=int, default=1200, help="Timestamp tolerance in ms")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[LEO-N] %(message)s")

    context = load_context(args.context)
    new_sat = get_new_satellite_state(context)
    ncc = context.ncc
    _, new_sat_id, _ = get_identifiers(context)
    tolerance = max(0, args.tolerance)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    sock.settimeout(1.0)

    logger.info("new satellite ready on %s:%d (relay %s:%d)", args.bind, args.port, args.old_host, args.old_port)

    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue

        try:
            payload = decode_envelope(data)
        except ValueError:
            logger.warning("discarding malformed packet from %s", addr)
            continue

        if payload.get("type") != "m5":
            logger.warning("unexpected message type=%s from %s", payload.get("type"), addr)
            continue

        cpu_before = sample_cpu()
        timer = Timer.start()

        try:
            response_payload = handle_m5(
                payload=payload,
                satellite=new_sat,
                ncc=ncc,
                expected_sat_id=new_sat_id,
                tolerance=tolerance,
            )
            cpu_after = sample_cpu()
            metrics = response_payload.get("metrics")
            if not isinstance(metrics, dict):
                metrics = {}
            metrics["cpu_ms_ln"] = float(metrics.get("cpu_ms_ln", 0.0)) + max(0.0, cpu_after.to_ms() - cpu_before.to_ms())
            metrics["processing_ms_ln"] = float(metrics.get("processing_ms_ln", 0.0)) + timer.stop_ms()
            response_payload["metrics"] = metrics
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("failed to process M5: %s", exc)
            tid = payload.get("tid", "")
            response_payload = {
                "type": "error",
                "tid": tid,
                "sat_id": new_sat_id,
                "stage": "new_satellite",
                "message": str(exc),
            }

        encoded = encode_envelope(response_payload)
        send_len = len(encoded)
        metrics = response_payload.setdefault("metrics", {})
        metrics["bytes_ln"] = float(metrics.get("bytes_ln", 0.0)) + send_len
        metrics["msgs_ln"] = int(metrics.get("msgs_ln", 0)) + 1
        response_payload["metrics"] = metrics
        encoded = encode_envelope(response_payload)
        sock.sendto(encoded, (args.old_host, args.old_port))


def handle_m5(
    *,
    payload: dict,
    satellite: SatelliteState,
    ncc,
    expected_sat_id: str,
    tolerance: int,
) -> dict:
    message = dict_to_m5(payload)
    if message.satellite_id != expected_sat_id:
        raise ValueError("unexpected satellite id in M5 payload")
    now = int(time.time() * 1000)
    if abs(now - message.T5) > tolerance:
        raise ValueError("stale switch request")
    if not validate_m5(ncc, message):
        raise ValueError("M5 equation failed")

    message_m6 = generate_m6(satellite, message, now)
    response = {"type": "m6"}
    response.update(m6_to_dict(message_m6))
    return response


def validate_m5(ncc, message: MessageM5) -> bool:
    try:
        user_record = ncc.get_user_public(message.tid)
    except KeyError:
        return False
    pk_i_public = point_from_bytes(user_record.pk_bytes)
    pk_i1_point = point_from_bytes(message.pk_i1_bytes)
    pk_ncc = ncc.public_point()
    d6_prime = hash_d6(message.tid, message.satellite_id, message.pk_i1_bytes, message.T5)
    lhs = message.alpha_i1 * generator()
    rhs = point_add(pk_i_public, d6_prime * pk_i1_point, pk_ncc)
    return lhs == rhs


def generate_m6(satellite: SatelliteState, message: MessageM5, now: int) -> MessageM6:
    r_n = random_scalar()
    pk_n_point = r_n * generator()
    pk_n_bytes = point_to_bytes(pk_n_point)
    d7 = hash_d7(message.tid, message.satellite_id, pk_n_bytes, now)
    alpha_n = normalize_scalar(satellite.sk_scalar + d7 * r_n)
    return MessageM6(
        tid=message.tid,
        satellite_id=satellite.satellite_id,
        pk_n_bytes=pk_n_bytes,
        alpha_n=alpha_n,
        T6=now,
    )


if __name__ == "__main__":
    main()
