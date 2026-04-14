#!/usr/bin/env python3
"""Old satellite (L_j) handling Guo2021 initial authentication and satellite switch."""

from __future__ import annotations

import argparse
import logging
import socket
import time
from pathlib import Path
from typing import Dict, Tuple

from metrics import sample_cpu

from guo2021 import (
    MessageM1,
    MessageM3,
    MessageM5,
    MessageM6,
    SatelliteState,
    generator,
    point_add,
    point_from_bytes,
    hash_d6,
)
from guo2021_codec import (
    decode_envelope,
    dict_to_m1,
    dict_to_m3,
    dict_to_m5,
    dict_to_m6,
    encode_envelope,
    m2_to_dict,
    m4_to_dict,
    m6_to_dict,
)
from guo2021_context import get_identifiers, get_old_satellite_state, load_context

logger = logging.getLogger("guo2021_old_sat")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Guo2021 old satellite relay/authenticator")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address for UE messages")
    parser.add_argument("--port", type=int, default=6000, help="UDP port for UE messages")
    parser.add_argument("--new-host", default="leo2", help="New satellite host")
    parser.add_argument("--new-port", type=int, default=5000, help="New satellite UDP port")
    parser.add_argument("--ground-host", default="ground", help="Ground station host")
    parser.add_argument("--ground-port", type=int, default=7000, help="Ground station UDP port")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--tolerance", type=int, default=1200, help="Timestamp tolerance in ms")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[LEO-J] %(message)s")

    context = load_context(args.context)
    old_sat: SatelliteState = get_old_satellite_state(context)
    ncc = context.ncc
    old_sat_id, new_sat_id, ground_id = get_identifiers(context)
    tolerance = max(0, args.tolerance)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    sock.settimeout(1.0)

    ground_endpoint = (args.ground_host, args.ground_port)
    new_sat_endpoint = (args.new_host, args.new_port)

    pending_auth: Dict[Tuple[str, str], Tuple[Tuple[str, int], float]] = {}
    pending_switch: Dict[Tuple[str, str], Dict[str, object]] = {}

    logger.info(
        "old satellite ready on %s:%d (new=%s:%d ground=%s:%d)",
        args.bind,
        args.port,
        args.new_host,
        args.new_port,
        args.ground_host,
        args.ground_port,
    )

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

        msg_type = payload.get("type")
        if msg_type == "m1":
            handle_m1(
                payload=payload,
                addr=addr,
                sock=sock,
                satellite=old_sat,
                expected_sat_id=old_sat_id,
                expected_ground_id=ground_id,
                ground_endpoint=ground_endpoint,
                pending=pending_auth,
                tolerance=tolerance,
            )
        elif msg_type == "m3":
            handle_m3(
                payload=payload,
                sock=sock,
                satellite=old_sat,
                pending=pending_auth,
                tolerance=tolerance,
            )
        elif msg_type == "m5":
            handle_m5(
                payload=payload,
                addr=addr,
                sock=sock,
                ncc=ncc,
                expected_new_sat=new_sat_id,
                new_sat_endpoint=new_sat_endpoint,
                pending=pending_switch,
                tolerance=tolerance,
            )
        elif msg_type == "m6":
            handle_m6(
                payload=payload,
                sock=sock,
                pending=pending_switch,
            )
        elif msg_type == "error":
            forward_error(payload, sock, pending_auth, pending_switch)
        else:
            logger.warning("unexpected message type=%s from %s", msg_type, addr)


def handle_m1(
    *,
    payload: Dict,
    addr: Tuple[str, int],
    sock: socket.socket,
    satellite: SatelliteState,
    expected_sat_id: str,
    expected_ground_id: str,
    ground_endpoint: Tuple[str, int],
    pending: Dict[Tuple[str, str], Tuple[Tuple[str, int], float]],
    tolerance: int,
) -> None:
    message = dict_to_m1(payload)
    if message.satellite_id != expected_sat_id or message.ground_id != expected_ground_id:
        logger.error(
            "M1 identifiers mismatch tid=%s sat=%s ground=%s", message.tid, message.satellite_id, message.ground_id
        )
        send_error(sock, addr, message.tid, "satellite_validate", "identifier mismatch")
        return

    now = int(time.time() * 1000)
    if abs(now - message.T1) > tolerance:
        logger.error("M1 timestamp stale tid=%s", message.tid)
        send_error(sock, addr, message.tid, "satellite_timestamp", "stale request")
        return

    try:
        response_m2 = satellite.process_m1(message, now=now, tolerance=tolerance)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("failed to process M1 tid=%s: %s", message.tid, exc)
        send_error(sock, addr, message.tid, "satellite_m1", str(exc))
        return

    key = (message.tid, message.ground_id)
    pending[key] = (addr, time.time())

    outbound = {"type": "m2"}
    outbound.update(m2_to_dict(response_m2))
    sock.sendto(encode_envelope(outbound), ground_endpoint)
    logger.info("forwarded M2 tid=%s to ground %s:%d", message.tid, ground_endpoint[0], ground_endpoint[1])


def handle_m3(
    *,
    payload: Dict,
    sock: socket.socket,
    satellite: SatelliteState,
    pending: Dict[Tuple[str, str], Tuple[Tuple[str, int], float]],
    tolerance: int,
) -> None:
    message, metrics = dict_to_m3(payload)
    key = (message.tid, message.ground_id)
    if key not in pending:
        logger.warning("received M3 for unknown session tid=%s", message.tid)
        return
    ue_addr, _ = pending.pop(key)

    now = int(time.time() * 1000)
    try:
        response_m4 = satellite.process_m3(message, now=now, tolerance=tolerance)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("failed to process M3 tid=%s: %s", message.tid, exc)
        send_error(sock, ue_addr, message.tid, "satellite_m3", str(exc))
        return

    outbound = {"type": "m4"}
    outbound.update(m4_to_dict(response_m4))
    if metrics:
        outbound["metrics"] = metrics
    sock.sendto(encode_envelope(outbound), ue_addr)
    logger.info("delivered M4 tid=%s to UE %s:%d", message.tid, ue_addr[0], ue_addr[1])


def handle_m5(
    *,
    payload: Dict,
    addr: Tuple[str, int],
    sock: socket.socket,
    ncc,
    expected_new_sat: str,
    new_sat_endpoint: Tuple[str, int],
    pending: Dict[Tuple[str, str], Dict[str, object]],
    tolerance: int,
) -> None:
    message = dict_to_m5(payload)
    if message.satellite_id != expected_new_sat:
        logger.error("M5 unexpected new satellite id=%s", message.satellite_id)
        send_error(sock, addr, message.tid, "relay_validate", "target satellite mismatch")
        return

    now = int(time.time() * 1000)
    if abs(now - message.T5) > tolerance:
        logger.error("M5 stale tid=%s", message.tid)
        send_error(sock, addr, message.tid, "relay_timestamp", "stale switch request")
        return

    if not validate_m5(ncc, message):
        logger.error("M5 equation failed tid=%s", message.tid)
        send_error(sock, addr, message.tid, "relay_equation", "invalid switch request")
        return

    cpu_before = sample_cpu()
    forwarded = payload.copy()
    forwarded["relay_id"] = payload.get("relay_id", "")
    encoded_forward = encode_envelope(forwarded)
    cpu_after = sample_cpu()
    cpu_ms = max(0.0, cpu_after.to_ms() - cpu_before.to_ms())

    key = (message.tid, message.satellite_id)
    pending[key] = {
        "ue_addr": addr,
        "start_time": time.time(),
        "cpu_ms": cpu_ms,
        "bytes_m5_out": len(encoded_forward),
    }

    sock.sendto(encoded_forward, new_sat_endpoint)
    logger.info("relayed M5 tid=%s to new satellite %s:%d", message.tid, new_sat_endpoint[0], new_sat_endpoint[1])


def handle_m6(
    *,
    payload: Dict,
    sock: socket.socket,
    pending: Dict[Tuple[str, str], Dict[str, object]],
) -> None:
    message = dict_to_m6(payload)
    key = (message.tid, message.satellite_id)
    if key not in pending:
        logger.warning("received M6 for unknown switch tid=%s", message.tid)
        return
    entry = pending.pop(key)
    ue_addr = entry["ue_addr"]

    cpu_before = sample_cpu()
    outbound = {"type": "m6"}
    outbound.update(m6_to_dict(message))

    metrics = payload.get("metrics")
    if not isinstance(metrics, dict):
        metrics = {}

    cpu_after = sample_cpu()
    cpu_ms = entry["cpu_ms"] + max(0.0, cpu_after.to_ms() - cpu_before.to_ms())
    metrics["cpu_ms_lj"] = float(metrics.get("cpu_ms_lj", 0.0)) + cpu_ms
    metrics["processing_ms_lj"] = float(metrics.get("processing_ms_lj", 0.0)) + 0.0

    encoded = encode_envelope(outbound)
    send_len = len(encoded)
    metrics["bytes_lj"] = float(metrics.get("bytes_lj", 0.0)) + entry.get("bytes_m5_out", 0.0) + send_len
    metrics["msgs_lj"] = int(metrics.get("msgs_lj", 0)) + 2
    outbound["metrics"] = metrics
    encoded = encode_envelope(outbound)

    sock.sendto(encoded, ue_addr)
    logger.info(
        "forwarded M6 tid=%s to UE %s:%d (elapsed %.2f ms)",
        message.tid,
        ue_addr[0],
        ue_addr[1],
        (time.time() - entry["start_time"]) * 1000.0,
    )


def forward_error(
    payload: Dict,
    sock: socket.socket,
    pending_auth: Dict[Tuple[str, str], Tuple[Tuple[str, int], float]],
    pending_switch: Dict[Tuple[str, str], Dict[str, object]],
) -> None:
    tid = payload.get("tid", "")
    sat_id = payload.get("sat_id")
    stage = payload.get("stage", "")
    if stage.startswith("new_satellite") or sat_id:
        key = (str(tid), str(sat_id))
        entry = pending_switch.pop(key, None)
        if entry:
            sock.sendto(encode_envelope(payload), entry["ue_addr"])
    else:
        ground_id = payload.get("gs_id", "")
        key = (str(tid), str(ground_id))
        entry = pending_auth.pop(key, None)
        if entry:
            sock.sendto(encode_envelope(payload), entry[0])


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


def send_error(sock: socket.socket, addr: Tuple[str, int], tid: str, stage: str, message: str) -> None:
    payload = {
        "type": "error",
        "tid": tid,
        "stage": stage,
        "message": message,
    }
    sock.sendto(encode_envelope(payload), addr)


if __name__ == "__main__":
    main()
