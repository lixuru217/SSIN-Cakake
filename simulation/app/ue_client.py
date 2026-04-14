#!/usr/bin/env python3
"""UE client used to trigger online SSINAuth authentications in the simulation."""

from __future__ import annotations

import argparse
import errno
import json
import socket
import sys
import time
from pathlib import Path

from context_utils import (
    get_ue_state,
    load_offline_context,
    load_sb_cache,
    load_ue_cache,
)
from handshake_codec import decode_response, encode_uplink
from metrics import Timer, sample_cpu
from ssinauth import UplinkRequest, finalize_authentication, prepare_uplink, timestamp_to_bytes


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="UE online authentication client")
    parser.add_argument("--context", type=Path, required=True, help="Path to offline context pickle")
    parser.add_argument("--ue-id", required=True, help="UE identifier (e.g. ue-001)")
    parser.add_argument("--auth-host", default="leo2", help="Authenticator hostname")
    parser.add_argument("--auth-port", type=int, default=5000, help="Authenticator UDP port")
    parser.add_argument("--timeout-ms", type=int, required=True, help="Per-attempt timeout in ms")
    parser.add_argument("--pto", type=int, default=0, help="Number of additional retries")
    parser.add_argument("--log-json", type=Path, help="Optional path to append JSON results")
    parser.add_argument("--cache-dir", type=Path, default=Path("/shared/preauth"))
    return parser


def _uplink_payload_len(request: UplinkRequest) -> int:
    """Approximate business payload size for an uplink attempt."""
    return (
        len(request.Q_bytes)
        + len(request.V1)
        + len(request.ue_canonical.encode("utf-8"))
        + len(timestamp_to_bytes(request.TS5))
    )


def write_result(record: dict, log_path: Path | None) -> None:
    line = json.dumps(record, separators=(",", ":"))
    print(line)
    sys.stdout.flush()
    if log_path is not None:
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def run_client(args: argparse.Namespace) -> None:
    context = load_offline_context(args.context)
    ue_record = get_ue_state(context, args.ue_id)
    authenticator = context.authenticator
    cache_dir = args.cache_dir
    ue_cache = load_ue_cache(cache_dir, args.ue_id)
    if ue_cache is not None:
        ue_record.pre_auth_cache = ue_cache
        ue_record.state.pre_auth_cache[ue_cache.target_id] = ue_cache
    sb_cache = load_sb_cache(cache_dir, args.ue_id)
    if sb_cache is not None:
        authenticator.incoming_sessions[ue_record.state.entity_id] = sb_cache

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout_ms / 1000.0)

    attempts_allowed = max(1, args.pto + 1)
    auth_bytes_total = 0
    auth_msgs_total = 0
    cpu_before = sample_cpu()
    wall_timer = Timer.start()
    t_start = None
    uplink_request: UplinkRequest | None = None
    response_payload = None
    failed_stage = None
    failed_errno = 0
    cpu_ms_leo2 = 0.0
    cached_request: UplinkRequest | None = None
    cached_payload: bytes | None = None
    cache_created_at: float | None = None
    cache_use_count = 0
    max_cache_age_ms = max(1, args.timeout_ms * 2)

    for attempt in range(attempts_allowed):
        cache_age_ms = (time.time() - cache_created_at) * 1000.0 if cache_created_at is not None else None
        cache_invalid = (
            cached_request is None
            or cached_payload is None
            or cache_use_count >= 1
            or (cache_age_ms is not None and cache_age_ms >= max_cache_age_ms)
        )
        if cache_invalid:
            ts5 = int(time.time() * 1000)
            cached_request = prepare_uplink(
                ue_record.state,
                authenticator,
                ts5=ts5,
                tolerance=args.timeout_ms * 2,
                fresh_reference=ts5,
            )
            cached_payload = encode_uplink(ue_record.state.canonical_id, cached_request)
            cache_created_at = time.time()
            cache_use_count = 0
        uplink_request = cached_request
        payload = cached_payload
        if t_start is None:
            t_start = time.time()
        sock.sendto(payload, (args.auth_host, args.auth_port))
        auth_bytes_total += _uplink_payload_len(uplink_request)
        auth_msgs_total += 1
        cache_use_count += 1
        try:
            data, _ = sock.recvfrom(8192)
        except socket.timeout:
            failed_stage = "timeout"
            failed_errno = errno.ETIMEDOUT
            continue

        try:
            response_payload = decode_response(data)
        except ValueError as exc:
            failed_stage = "decode_error"
            failed_errno = errno.EPROTO
            continue

        if response_payload.get("status") != "ok":
            failed_stage = response_payload.get("failed_stage", "authenticator_error")
            failed_errno = errno.EPROTO
            continue

        cpu_ms_leo2 = float(response_payload.get("cpu_ms", 0.0))
        break
    else:
        cpu_after = sample_cpu()
        wall_ms = wall_timer.stop_ms()
        cpu_delta_ms = max(0.0, cpu_after.to_ms() - cpu_before.to_ms())
        record = {
            "status": "failed",
            "failed_stage": failed_stage or "no_response",
            "errno": failed_errno,
            "attempts": auth_msgs_total,
            "timeout_ms": args.timeout_ms,
            "pto": args.pto,
            "latency_ms": wall_ms,
            "cpu_ms_ue": cpu_delta_ms,
            "cpu_ms_leo2": cpu_ms_leo2,
            "bytes_online": auth_bytes_total,
            "msgs_online": auth_msgs_total,
        }
        write_result(record, args.log_json)
        return

    if response_payload is None or response_payload.get("status") != "ok":
        cpu_after = sample_cpu()
        wall_ms = wall_timer.stop_ms()
        cpu_delta_ms = max(0.0, cpu_after.to_ms() - cpu_before.to_ms())
        record = {
            "status": "failed",
            "failed_stage": failed_stage or "authenticator_error",
            "errno": failed_errno,
            "attempts": auth_msgs_total,
            "timeout_ms": args.timeout_ms,
            "pto": args.pto,
            "latency_ms": wall_ms,
            "cpu_ms_ue": cpu_delta_ms,
            "cpu_ms_leo2": cpu_ms_leo2,
            "bytes_online": auth_bytes_total,
            "msgs_online": auth_msgs_total,
        }
        write_result(record, args.log_json)
        return

    assert uplink_request is not None

    ts6 = int(response_payload["ts6"])
    q_b = bytes.fromhex(response_payload["q_b"])
    v2 = bytes.fromhex(response_payload["v2"])

    finalize_authentication(
        ue_record.state,
        authenticator,
        uplink_request,
        q_b,
        v2,
        ts6=ts6,
        tolerance=args.timeout_ms * 2,
        fresh_reference=uplink_request.TS5,
        derive_session_key=False,
    )

    cpu_after = sample_cpu()
    wall_ms = wall_timer.stop_ms()
    cpu_delta_ms = max(0.0, cpu_after.to_ms() - cpu_before.to_ms())

    record = {
        "status": "ok",
        "attempts": auth_msgs_total,
        "timeout_ms": args.timeout_ms,
        "pto": args.pto,
        "latency_ms": wall_ms,
        "bytes_online": auth_bytes_total,
        "msgs_online": auth_msgs_total,
        "cpu_ms_ue": cpu_delta_ms,
        "cpu_ms_leo2": cpu_ms_leo2,
        "ts5": uplink_request.TS5,
        "ts6": ts6,
    }
    write_result(record, args.log_json)


def main() -> None:
    args = build_arg_parser().parse_args()
    args.cache_dir = args.cache_dir.resolve()
    run_client(args)


if __name__ == "__main__":
    main()
