#!/usr/bin/env python3
"""UE client for Liu2022 access authentication in the simulator."""

from __future__ import annotations

import argparse
import json
import socket
import time
from pathlib import Path

from metrics import Timer, sample_cpu

import liu2022
from liu2022_codec import access_request_to_dict, dict_to_access_response, decode_envelope, encode_envelope
from liu2022_context import get_ue_state, load_context, load_ue_runtime, save_ue_runtime


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Liu2022 UE authentication client")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle")
    parser.add_argument("--ue-id", required=True, help="UE identifier")
    parser.add_argument("--ap-host", default="ap1", help="AP host")
    parser.add_argument("--ap-port", type=int, default=6000, help="AP UDP port")
    parser.add_argument("--timeout-ms", type=int, required=True, help="Per-attempt timeout in ms")
    parser.add_argument("--pto", type=int, default=0, help="Number of additional retries")
    parser.add_argument("--cache-dir", type=Path, default=Path("/shared/runtime"))
    parser.add_argument("--log-json", type=Path, help="Optional path to append JSON results")
    return parser


def write_result(record: dict, log_path: Path | None) -> None:
    line = json.dumps(record, separators=(",", ":"))
    print(line, flush=True)
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")



def _scalar_size(value: int) -> int:
    return 1 if value == 0 else (value.bit_length() + 7) // 8


def _masked_identity_payload_len(identity: liu2022.MaskedIdentity) -> int:
    return (
        len(identity.p_id)
        + len(identity.p_pk)
        + _scalar_size(int(identity.index_id))
        + _scalar_size(int(identity.index_pk))
    )


def _access_request_payload_len(request: liu2022.AccessRequest) -> int:
    return (
        _masked_identity_payload_len(request.identity)
        + len(request.pk_ue_ep_bytes)
        + _scalar_size(int(request.v_ue))
    )


def run_client(args: argparse.Namespace) -> None:
    context = load_context(args.context)
    runtime_state = load_ue_runtime(args.cache_dir, args.ue_id)
    ue_state = runtime_state if runtime_state is not None else get_ue_state(context, args.ue_id)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(max(0.5, args.timeout_ms / 1000.0))

    attempts_allowed = max(1, args.pto + 1)
    total_attempts = 0
    total_bytes = 0
    total_msgs = 0
    overall_timer = Timer.start()
    result_payload = None

    for attempt_index in range(1, attempts_allowed + 1):
        cpu_before = sample_cpu()
        attempt_timer = Timer.start()
        ts1 = int(time.time() * 1000)
        request = ue_state.create_access_request(ts1)
        payload = access_request_to_dict(request)
        packet = encode_envelope(payload)
        sock.sendto(packet, (args.ap_host, args.ap_port))

        payload_bytes = _access_request_payload_len(request)
        total_attempts += 1
        total_bytes += payload_bytes
        total_msgs += 1

        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            cpu_after = sample_cpu()
            result_payload = {
                "status": "timeout",
                "failed_stage": "wait_access_response",
                "errno": 0,
                "attempts": total_attempts,
                "timeout_ms": args.timeout_ms,
                "pto": args.pto,
                "latency_ms": attempt_timer.stop_ms(),
                "bytes_online": total_bytes,
                "msgs_online": total_msgs,
                "cpu_ms_ue": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                "cpu_ms_ap": 0.0,
                "processing_ms_ap": 0.0,
                "ts1": ts1,
                "ts2": "",
            }
            continue

        try:
            response_payload = decode_envelope(data)
        except ValueError:
            result_payload = {
                "status": "failed",
                "failed_stage": "decode_response",
                "errno": 0,
                "attempts": total_attempts,
                "timeout_ms": args.timeout_ms,
                "pto": args.pto,
                "latency_ms": attempt_timer.stop_ms(),
                "bytes_online": total_bytes,
                "msgs_online": total_msgs,
                "cpu_ms_ue": max(0.0, sample_cpu().to_ms() - cpu_before.to_ms()),
                "cpu_ms_ap": 0.0,
                "processing_ms_ap": 0.0,
                "ts1": ts1,
                "ts2": "",
            }
            continue

        if response_payload.get("type") == "error":
            result_payload = {
                "status": "failed",
                "failed_stage": str(response_payload.get("stage", "ap_error")),
                "errno": 0,
                "attempts": total_attempts,
                "timeout_ms": args.timeout_ms,
                "pto": args.pto,
                "latency_ms": attempt_timer.stop_ms(),
                "bytes_online": total_bytes,
                "msgs_online": total_msgs,
                "cpu_ms_ue": max(0.0, sample_cpu().to_ms() - cpu_before.to_ms()),
                "cpu_ms_ap": 0.0,
                "processing_ms_ap": 0.0,
                "ts1": ts1,
                "ts2": "",
                "message": str(response_payload.get("message", "")),
            }
            continue

        if response_payload.get("type") != "access_response":
            result_payload = {
                "status": "failed",
                "failed_stage": "unexpected_type",
                "errno": 0,
                "attempts": total_attempts,
                "timeout_ms": args.timeout_ms,
                "pto": args.pto,
                "latency_ms": attempt_timer.stop_ms(),
                "bytes_online": total_bytes,
                "msgs_online": total_msgs,
                "cpu_ms_ue": max(0.0, sample_cpu().to_ms() - cpu_before.to_ms()),
                "cpu_ms_ap": 0.0,
                "processing_ms_ap": 0.0,
                "ts1": ts1,
                "ts2": "",
            }
            continue

        metrics = response_payload.get("metrics", {}) if isinstance(response_payload.get("metrics"), dict) else {}
        response = dict_to_access_response(response_payload)
        try:
            ue_state.process_access_response(
                response,
                now=int(time.time() * 1000),
                tolerance_ms=args.timeout_ms * 2,
            )
        except Exception as exc:  # pylint: disable=broad-except
            result_payload = {
                "status": "failed",
                "failed_stage": "ue_finalize",
                "errno": 0,
                "attempts": total_attempts,
                "timeout_ms": args.timeout_ms,
                "pto": args.pto,
                "latency_ms": attempt_timer.stop_ms(),
                "bytes_online": total_bytes,
                "msgs_online": total_msgs,
                "cpu_ms_ue": max(0.0, sample_cpu().to_ms() - cpu_before.to_ms()),
                "cpu_ms_ap": float(metrics.get("cpu_ms", 0.0)),
                "processing_ms_ap": float(metrics.get("processing_ms", 0.0)),
                "ts1": ts1,
                "ts2": response.ts2,
                "message": str(exc),
            }
            continue

        cpu_after = sample_cpu()
        overall_latency_ms = overall_timer.stop_ms()
        cpu_ms_ue = max(0.0, cpu_after.to_ms() - cpu_before.to_ms())

        result_payload = {
            "status": "ok",
            "attempts": total_attempts,
            "timeout_ms": args.timeout_ms,
            "pto": args.pto,
            "latency_ms": overall_latency_ms,
            "bytes_online": total_bytes,
            "msgs_online": total_msgs,
            "cpu_ms_ue": cpu_ms_ue,
            "cpu_ms_ap": float(metrics.get("cpu_ms", 0.0)),
            "processing_ms_ap": float(metrics.get("processing_ms", 0.0)),
            "ts1": ts1,
            "ts2": response.ts2,
        }
        save_ue_runtime(args.cache_dir, args.ue_id, ue_state)
        break
    else:
        if result_payload is None:
            result_payload = {
                "status": "failed",
                "failed_stage": "no_response",
                "errno": 0,
                "attempts": total_attempts,
                "timeout_ms": args.timeout_ms,
                "pto": args.pto,
                "latency_ms": overall_timer.stop_ms(),
                "bytes_online": total_bytes,
                "msgs_online": total_msgs,
                "cpu_ms_ue": 0.0,
                "cpu_ms_ap": 0.0,
                "processing_ms_ap": 0.0,
                "ts1": "",
                "ts2": "",
            }

    write_result(result_payload, args.log_json)


def main() -> None:
    args = build_parser().parse_args()
    args.cache_dir = args.cache_dir.resolve()
    run_client(args)


if __name__ == "__main__":
    main()
