#!/usr/bin/env python3
"""UE client driving the Guo2021 satellite switch (M5/M6) authentication."""

from __future__ import annotations

import argparse
import json
import socket
import time
from pathlib import Path

from metrics import Timer, sample_cpu

from guo2021 import MessageM6
from guo2021_codec import decode_envelope, dict_to_m6, encode_envelope, m5_to_dict
from guo2021_context import (
    get_identifiers,
    get_ue_credentials,
    get_ue_session_id,
    get_ue_state,
    load_context,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Guo2021 UE satellite-switch client")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle")
    parser.add_argument("--ue-id", required=True, help="UE identifier (e.g. ue-001)")
    parser.add_argument("--old-sat-host", default="leo1", help="Old satellite host (relay)")
    parser.add_argument("--old-sat-port", type=int, default=6000, help="Old satellite UDP port")
    parser.add_argument("--timeout-ms", type=int, required=True, help="Per-attempt timeout in ms")
    parser.add_argument("--pto", type=int, default=0, help="Number of additional retries")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    run_client(args)


def run_client(args: argparse.Namespace) -> None:
    context = load_context(args.context)
    ue_state = get_ue_state(context, args.ue_id)
    password, biometric = get_ue_credentials(context, args.ue_id)
    if not ue_state.validate_local_login(password, biometric):
        raise RuntimeError("local verification failed before switch attempt")

    session_id = get_ue_session_id(context, args.ue_id)
    old_sat_id, new_sat_id, _ = get_identifiers(context)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(max(0.5, args.timeout_ms / 1000.0))

    attempts = max(1, args.pto + 1)
    result_payload = None
    attempt_number = 0

    for attempt in range(attempts):
        attempt_number = attempt + 1
        cpu_before = sample_cpu()
        wall_timer = Timer.start()

        T5 = int(time.time() * 1000)
        message_m5 = ue_state.prepare_satellite_switch(
            session=session_id,
            target_satellite=new_sat_id,
            T5=T5,
        )
        payload = {"type": "m5", "ue_id": args.ue_id}
        payload.update(m5_to_dict(message_m5))
        packet = encode_envelope(payload)

        sock.sendto(packet, (args.old_sat_host, args.old_sat_port))
        bytes_sent = len(packet)
        bytes_recv = 0
        bytes_online = bytes_sent
        msgs_online = 1

        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            cpu_after = sample_cpu()
            result_payload = {
                "status": "timeout",
                "failed_stage": "wait_m6",
                "errno": 0,
                "attempts": attempt_number,
                "timeout_ms": args.timeout_ms,
                "pto": args.pto,
                "latency_ms": wall_timer.stop_ms(),
                "bytes_online": float(bytes_online),
                "msgs_online": msgs_online,
                "cpu_ms_ue": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                "cpu_ms_lj": 0.0,
                "cpu_ms_ln": 0.0,
                "processing_ms_ln": 0.0,
                "bytes_ue": float(bytes_online),
                "bytes_lj": 0.0,
                "bytes_ln": 0.0,
                "msgs_ue": msgs_online,
                "msgs_lj": 0,
                "msgs_ln": 0,
                "msgs_total": msgs_online,
                "bytes_total": float(bytes_online),
                "ts5": T5,
                "ts6": "",
            }
            continue

        msgs_online += 1
        bytes_recv = len(data)
        bytes_online = bytes_sent + bytes_recv

        try:
            response = decode_envelope(data)
        except ValueError:
            result_payload = _failure(
                stage="decode",
                attempts=attempt_number,
                msgs_online=msgs_online,
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                bytes_online=bytes_online,
                cpu_before=cpu_before,
                timer=wall_timer,
                message="invalid response payload",
                ts5=T5,
            )
            continue

        if response.get("type") == "error":
            result_payload = _failure(
                stage=str(response.get("stage", "relay_error")),
                attempts=attempt_number,
                msgs_online=msgs_online,
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                bytes_online=bytes_online,
                cpu_before=cpu_before,
                timer=wall_timer,
                message=str(response.get("message", "")),
                ts5=T5,
            )
            continue

        if response.get("type") != "m6":
            result_payload = _failure(
                stage="unexpected_type",
                attempts=attempt_number,
                msgs_online=msgs_online,
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                bytes_online=bytes_online,
                cpu_before=cpu_before,
                timer=wall_timer,
                message=f"unexpected message type {response.get('type')}",
                ts5=T5,
            )
            continue

        message_m6 = dict_to_m6(response)
        try:
            ue_state.finalize_satellite_switch(
                new_sat_id,
                message_m6,
                now=int(time.time() * 1000),
                tolerance=args.timeout_ms * 2,
            )
        except Exception as exc:  # pylint: disable=broad-except
            result_payload = _failure(
                stage="ue_finalize",
                attempts=attempt_number,
                msgs_online=msgs_online,
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                bytes_online=bytes_online,
                cpu_before=cpu_before,
                timer=wall_timer,
                message=str(exc),
                ts5=T5,
            )
            continue

        cpu_after = sample_cpu()
        cpu_ms_ue = max(0.0, cpu_after.to_ms() - cpu_before.to_ms())
        wall_ms = wall_timer.stop_ms()

        metrics = response.get("metrics", {}) if isinstance(response.get("metrics"), dict) else {}
        cpu_ms_lj = float(metrics.get("cpu_ms_lj", 0.0))
        cpu_ms_ln = float(metrics.get("cpu_ms_ln", 0.0))
        processing_ms_ln = float(metrics.get("processing_ms_ln", 0.0))
        bytes_lj = float(metrics.get("bytes_lj", 0.0))
        bytes_ln = float(metrics.get("bytes_ln", 0.0))
        msgs_lj = int(metrics.get("msgs_lj", 0))
        msgs_ln = int(metrics.get("msgs_ln", 0))

        msgs_ue = 2
        bytes_ue = float(bytes_online)
        total_msgs = msgs_ue + msgs_lj + msgs_ln
        total_bytes = bytes_ue + bytes_lj + bytes_ln

        result_payload = {
            "status": "ok",
            "attempts": attempt_number,
            "timeout_ms": args.timeout_ms,
            "pto": args.pto,
            "latency_ms": wall_ms,
            "bytes_online": total_bytes,
            "msgs_online": total_msgs,
            "cpu_ms_ue": cpu_ms_ue,
            "cpu_ms_lj": cpu_ms_lj,
            "cpu_ms_ln": cpu_ms_ln,
            "processing_ms_ln": processing_ms_ln,
            "bytes_ue": bytes_ue,
            "bytes_lj": bytes_lj,
            "bytes_ln": bytes_ln,
            "msgs_ue": msgs_ue,
            "msgs_lj": msgs_lj,
            "msgs_ln": msgs_ln,
            "msgs_total": total_msgs,
            "bytes_total": total_bytes,
            "ts5": T5,
            "ts6": message_m6.T6,
        }
        break
    else:
        if result_payload is None:
            result_payload = _failure(
                stage="no_response",
                attempts=attempt_number,
                msgs_online=0,
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                bytes_online=0,
                cpu_before=sample_cpu(),
                timer=Timer.start(),
                message="no successful attempt",
                ts5="",
            )

    print(json.dumps(result_payload, separators=(",", ":")))


def _failure(
    *,
    stage: str,
    attempts: int,
    msgs_online: int,
    timeout_ms: int,
    pto: int,
    bytes_online: int,
    cpu_before,
    timer: Timer,
    message: str,
    ts5,
) -> dict:
    cpu_after = sample_cpu()
    return {
        "status": "failed",
        "failed_stage": stage,
        "errno": 0,
        "attempts": attempts,
        "timeout_ms": timeout_ms,
        "pto": pto,
        "latency_ms": timer.stop_ms(),
        "bytes_online": float(bytes_online),
        "msgs_online": msgs_online,
        "cpu_ms_ue": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
        "cpu_ms_lj": 0.0,
        "cpu_ms_ln": 0.0,
        "processing_ms_ln": 0.0,
        "bytes_ue": float(bytes_online),
        "bytes_lj": 0.0,
        "bytes_ln": 0.0,
        "msgs_ue": attempts,
        "msgs_lj": 0,
        "msgs_ln": 0,
        "msgs_total": attempts,
        "bytes_total": float(bytes_online),
        "ts5": ts5,
        "ts6": "",
        "message": message,
    }


if __name__ == "__main__":
    main()
