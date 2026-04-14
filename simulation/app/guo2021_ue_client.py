#!/usr/bin/env python3
"""UE client for Guo2021 online authentication in the simulator."""

from __future__ import annotations

import argparse
import copy
import json
import socket
import time
from pathlib import Path

from metrics import Timer, sample_cpu

from guo2021 import AccessResult, MessageM1, UserDeviceState
from guo2021_codec import decode_envelope, dict_to_m4, encode_envelope, m1_to_dict
from guo2021_context import get_identifiers, get_old_satellite_state, get_ue_credentials, get_ue_state, load_context


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Guo2021 UE authentication client")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle")
    parser.add_argument("--ue-id", required=True, help="UE identifier (e.g. ue-001)")
    parser.add_argument("--sat-host", default="leo1", help="Satellite host")
    parser.add_argument("--sat-port", type=int, default=6000, help="Satellite UDP port")
    parser.add_argument("--timeout-ms", type=int, required=True, help="Per-attempt timeout in ms")
    parser.add_argument("--pto", type=int, default=0, help="Number of additional retries")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    run_client(args)


def _scalar_size(value: int) -> int:
    return 1 if value == 0 else (value.bit_length() + 7) // 8


def _m1_payload_len(message: MessageM1) -> int:
    return len(message.pk_i_bytes) + _scalar_size(message.alpha_i)


def run_client(args: argparse.Namespace) -> None:
    context = load_context(args.context)
    base_state: UserDeviceState = get_ue_state(context, args.ue_id)
    password, biometric = get_ue_credentials(context, args.ue_id)
    if not base_state.validate_local_login(password, biometric):
        raise RuntimeError("local login self-check failed")

    satellite = get_old_satellite_state(context)
    _, _, ground_id = get_identifiers(context)
    sat_id = satellite.satellite_id

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout_ms / 1000.0)

    attempts_allowed = max(1, args.pto + 1)
    result_payload = None
    attempt_number = 0

    for attempt in range(attempts_allowed):
        attempt_number = attempt + 1
        ue_state = copy.deepcopy(base_state)
        cpu_before = sample_cpu()
        timer = Timer.start()

        T1 = int(time.time() * 1000)
        m1 = ue_state.start_access(sat_id, ground_id, T1)
        payload = {"type": "m1"}
        payload.update(m1_to_dict(m1))
        packet = encode_envelope(payload)
        sock.sendto(packet, (args.sat_host, args.sat_port))

        bytes_online = _m1_payload_len(m1)
        msgs_online = 1

        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            result_payload = {
                "status": "timeout",
                "failed_stage": "wait_m4",
                "errno": 0,
                "attempts": attempt_number,
                "timeout_ms": args.timeout_ms,
                "pto": args.pto,
                "latency_ms": timer.stop_ms(),
                "bytes_online": bytes_online,
                "msgs_online": msgs_online,
                "cpu_ms_ue": max(0.0, sample_cpu().to_ms() - cpu_before.to_ms()),
                "cpu_ms_leo2": 0.0,
                "ts1": T1,
                "ts4": "",
            }
            continue

        msgs_online += 1

        try:
            payload_resp = decode_envelope(data)
        except ValueError:
            result_payload = failure_payload(
                stage="decode",
                attempts=attempt_number,
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                bytes_online=bytes_online,
                cpu_before=cpu_before,
                timer=timer,
                message="invalid JSON payload",
                ts1=T1,
            )
            continue

        msg_type = payload_resp.get("type")
        if msg_type == "error":
            result_payload = failure_payload(
                stage=str(payload_resp.get("stage", "satellite_error")),
                attempts=attempt_number,
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                bytes_online=bytes_online,
                cpu_before=cpu_before,
                timer=timer,
                message=str(payload_resp.get("message", "")),
                ts1=T1,
            )
            continue

        if msg_type != "m4":
            result_payload = failure_payload(
                stage="unexpected_type",
                attempts=attempt_number,
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                bytes_online=bytes_online,
                cpu_before=cpu_before,
                timer=timer,
                message=f"unexpected message type {msg_type}",
                ts1=T1,
            )
            continue

        message_m4, metrics = dict_to_m4(payload_resp)
        try:
            result: AccessResult = ue_state.finalize_access(
                message_m4,
                now=int(time.time() * 1000),
                tolerance=args.timeout_ms * 2,
            )
        except Exception as exc:  # pylint: disable=broad-except
            result_payload = failure_payload(
                stage="ue_finalize",
                attempts=attempt_number,
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                bytes_online=bytes_online,
                cpu_before=cpu_before,
                timer=timer,
                message=str(exc),
                ts1=T1,
            )
            continue

        cpu_after = sample_cpu()
        cpu_ms_ue = max(0.0, cpu_after.to_ms() - cpu_before.to_ms())
        wall_ms = timer.stop_ms()

        result_payload = {
            "status": "ok",
            "attempts": attempt_number,
            "timeout_ms": args.timeout_ms,
            "pto": args.pto,
            "latency_ms": wall_ms,
            "bytes_online": bytes_online,
            "msgs_online": msgs_online,
            "cpu_ms_ue": cpu_ms_ue,
            "cpu_ms_leo2": float(metrics.get("cpu_ms_ground", 0.0)),
            "processing_ms_ground": float(metrics.get("processing_ms_ground", 0.0)),
            "ts1": T1,
            "ts4": message_m4.T4,
            "session_key_hex": result.session_key.hex(),
            "shared_point_hex": result.shared_point_bytes.hex(),
        }
        break
    else:
        if result_payload is None:
            result_payload = failure_payload(
                stage="no_response",
                attempts=attempt_number,
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                bytes_online=0,
                cpu_before=sample_cpu(),
                timer=Timer.start(),
                message="no successful attempt",
                ts1="",
            )

    print(json.dumps(result_payload, separators=(",", ":")))


def failure_payload(
    *,
    stage: str,
    attempts: int,
    timeout_ms: int,
    pto: int,
    bytes_online: int,
    cpu_before,
    timer: Timer,
    message: str,
    ts1,
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
        "bytes_online": bytes_online,
        "msgs_online": attempts,
        "cpu_ms_ue": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
        "cpu_ms_leo2": 0.0,
        "processing_ms_ground": 0.0,
        "ts1": ts1,
        "ts4": "",
        "message": message,
    }


if __name__ == "__main__":
    main()
