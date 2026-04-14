#!/usr/bin/env python3
"""UE client driving the Zhu2023 RSU handover handshake."""

from __future__ import annotations

import argparse
import json
import socket
import time
from pathlib import Path

from metrics import Timer, sample_cpu
import zhu2023
from zhu2023_codec import decode_payload, encode_switch_request, ensure_type
from zhu2023_context import get_rsu_ids, get_vehicle_state, load_context


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Zhu2023 UE handover client")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle path")
    parser.add_argument("--ue-id", required=True, help="Vehicle identifier to use")
    parser.add_argument(
        "--rsu-host",
        "--old-rsu-host",
        default="rsu",
        dest="rsu_host",
        help="Target RSU host (alias: --old-rsu-host)",
    )
    parser.add_argument(
        "--rsu-port",
        "--old-rsu-port",
        dest="rsu_port",
        type=int,
        default=6000,
        help="Target RSU UDP port (alias: --old-rsu-port)",
    )
    parser.add_argument("--timeout-ms", type=int, required=True, help="Per-attempt timeout in milliseconds")
    parser.add_argument("--pto", type=int, default=0, help="Additional retry attempts")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    run_client(args)


def _scalar_size(value: int) -> int:
    return 1 if value == 0 else (value.bit_length() + 7) // 8


def _broadcast_payload_len(broadcast: zhu2023.SignedBroadcast) -> int:
    pseudo = broadcast.pseudo_id
    public_key = broadcast.public_key
    signature = broadcast.signature
    total = len(broadcast.message)
    total += len(pseudo.component1) + len(pseudo.component2)
    total += len(public_key.B_i) + len(public_key.R_i)
    total += len(signature.U_i) + _scalar_size(int(signature.delta_i))
    return total


def run_client(args: argparse.Namespace) -> None:
    context = load_context(args.context)
    vehicle_state = get_vehicle_state(context, args.ue_id)
    _, target_rsu = get_rsu_ids(context)
    rsu_id = target_rsu

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(max(0.5, args.timeout_ms / 1000.0))

    attempts_allowed = max(1, args.pto + 1)
    result_payload = None

    total_bytes_sent = 0
    total_msgs_sent = 0
    last_timestamp = None

    for attempt in range(attempts_allowed):
        attempt_number = attempt + 1
        cpu_before = sample_cpu()
        timer = Timer.start()
        timestamp = int(time.time() * 1000)
        last_timestamp = timestamp
        message = f"handover|ue={args.ue_id}|target={rsu_id}|ts={timestamp}".encode("utf-8")
        try:
            broadcast = vehicle_state.sign(message, timestamp)
        except Exception as exc:  # pylint: disable=broad-except
            result_payload = failure_record(
                stage="sign",
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                attempts=attempt_number,
                cpu_before=cpu_before,
                timer=timer,
                message=str(exc),
                bytes_online=0.0,
                msgs_online=total_msgs_sent,
                ts5=timestamp,
            )
            continue

        packet = encode_switch_request(args.ue_id, rsu_id, broadcast)
        sock.sendto(packet, (args.rsu_host, args.rsu_port))
        bytes_sent = _broadcast_payload_len(broadcast)
        total_bytes_sent += bytes_sent
        total_msgs_sent += 1

        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            result_payload = failure_record(
                stage="timeout_wait_response",
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                attempts=attempt_number,
                cpu_before=cpu_before,
                timer=timer,
                message="no response within timeout",
                bytes_online=total_bytes_sent,
                msgs_online=total_msgs_sent,
                ts5=timestamp,
            )
            continue

        try:
            response = ensure_type(decode_payload(data), "switch_response")
        except Exception as exc:  # pylint: disable=broad-except
            result_payload = failure_record(
                stage="decode_response",
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                attempts=attempt_number,
                cpu_before=cpu_before,
                timer=timer,
                message=str(exc),
                bytes_online=total_bytes_sent,
                msgs_online=total_msgs_sent,
                ts5=timestamp,
            )
            continue

        status = response.get("status")
        metrics = response.get("metrics", {}) if isinstance(response.get("metrics"), dict) else {}
        cpu_after = sample_cpu()
        cpu_ms_ue = max(0.0, cpu_after.to_ms() - cpu_before.to_ms())
        latency_ms = timer.stop_ms()
        ts_ack = response.get("ts_ack", "")

        if status != "ok":
            result_payload = failure_record(
                stage="rsu_status",
                timeout_ms=args.timeout_ms,
                pto=args.pto,
                attempts=attempt_number,
                cpu_before=cpu_before,
                timer=Timer.start(),  # provide zero duration for failure structure
                message=response.get("message", "rsu reported failure"),
                bytes_online=total_bytes_sent,
                msgs_online=total_msgs_sent,
                ts5=timestamp,
            )
            result_payload["cpu_ms_ue"] = cpu_ms_ue
            result_payload["latency_ms"] = latency_ms
            result_payload["bytes_online"] = float(total_bytes_sent)
            result_payload["msgs_online"] = total_msgs_sent
            continue

        result_payload = {
            "status": "ok",
            "failed_stage": "",
            "errno": 0,
            "attempts": attempt_number,
            "timeout_ms": args.timeout_ms,
            "pto": args.pto,
            "latency_ms": latency_ms,
            "bytes_online": float(total_bytes_sent),
            "msgs_online": total_msgs_sent,
            "cpu_ms_ue": cpu_ms_ue,
            "cpu_ms_leo2": float(metrics.get("cpu_ms_leo2", 0.0)),
            "processing_ms_leo2": float(metrics.get("processing_ms_leo2", 0.0)),
            "bytes_ue": float(total_bytes_sent),
            "bytes_leo2": float(metrics.get("bytes_leo2", 0.0)),
            "msgs_ue": total_msgs_sent,
            "msgs_leo2": int(metrics.get("msgs_leo2", 0)),
            "ts5": timestamp,
            "ts6": ts_ack,
        }
        break

    if result_payload is None:
        result_payload = failure_record(
            stage="no_success",
            timeout_ms=args.timeout_ms,
            pto=args.pto,
            attempts=attempts_allowed,
            cpu_before=sample_cpu(),
            timer=Timer.start(),
            message="no successful attempt",
            bytes_online=0.0,
            msgs_online=total_msgs_sent,
            ts5=last_timestamp,
        )

    sock.close()
    print(json.dumps(result_payload, separators=(",", ":")))


def failure_record(
    *,
    stage: str,
    timeout_ms: int,
    pto: int,
    attempts: int,
    cpu_before,
    timer: Timer,
    message: str,
    bytes_online: float,
    msgs_online: int,
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
        "cpu_ms_leo2": 0.0,
        "bytes_ue": float(bytes_online),
        "bytes_leo2": 0.0,
        "msgs_ue": msgs_online,
        "msgs_leo2": 0,
        "message": message,
        "ts5": ts5 if ts5 is not None else "",
        "ts6": "",
    }


if __name__ == "__main__":
    main()
