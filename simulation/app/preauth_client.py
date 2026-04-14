#!/usr/bin/env python3
"""UE-side pre-authentication trigger for SSINAuth."""

from __future__ import annotations

import argparse
import json
import logging
import socket
import time
from pathlib import Path

from bn254.ecp import generator
from context_utils import load_offline_context, write_ue_cache
from handshake_codec import decode_secure_message, encode_secure_message, envelope_from_payload
from ssinauth import (
    UEPreAuthCache,
    compute_pid,
    point_to_bytes,
    random_scalar,
    scalar_to_bytes,
    timestamp_to_bytes,
)

logger = logging.getLogger("preauth_client")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Trigger SSINAuth pre-authentication")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle path")
    parser.add_argument("--ue-id", required=True, help="UE identifier")
    parser.add_argument("--helper-host", default="leo1", help="LEO1 relay host")
    parser.add_argument("--helper-port", type=int, default=6000, help="LEO1 relay UDP port")
    parser.add_argument("--cache-dir", type=Path, default=Path("/shared/preauth"))
    parser.add_argument("--timeout", type=float, default=5.0, help="socket timeout seconds")
    parser.add_argument("--log-level", default="INFO")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[UE-PREAUTH] %(message)s")

    context = load_offline_context(args.context)
    if args.ue_id not in context.ue_records:
        raise KeyError(f"UE {args.ue_id} not registered")
    ue_record = context.ue_records[args.ue_id]
    helper = context.helper
    authenticator = context.authenticator
    channel_ue_helper = ue_record.channel

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)

    m_i = random_scalar()
    M_i_point = m_i * generator()
    M_i_bytes = point_to_bytes(M_i_point)
    pid_i = compute_pid(ue_record.state.identity_bytes, M_i_bytes)
    ts1 = int(time.time() * 1000)

    step1_payload = {
        "h_i": scalar_to_bytes(ue_record.state.h),
        "M_i": M_i_bytes,
        "PID_i": pid_i,
        "TS1": timestamp_to_bytes(ts1),
    }

    envelope1 = channel_ue_helper.encrypt(step1_payload)
    message1 = encode_secure_message("preauth_step1", args.ue_id, envelope1, ts1=ts1)
    sock.sendto(message1, (args.helper_host, args.helper_port))
    logger.info("sent step1 to helper ue=%s", args.ue_id)

    try:
        data4, addr = sock.recvfrom(8192)
    except socket.timeout:
        result = {"status": "timeout", "stage": "step4_wait"}
        print(json.dumps(result))
        return

    payload4 = decode_secure_message(data4)
    if payload4.get("type") != "preauth_step4" or payload4.get("ue_id") != args.ue_id:
        result = {"status": "error", "stage": "step4_type"}
        print(json.dumps(result))
        return

    envelope4 = envelope_from_payload(payload4)
    step4 = channel_ue_helper.decrypt(envelope4)

    h_B = int.from_bytes(step4["h_B"], "big")
    M_B_bytes = step4["M_B"]
    pid_target = step4["PID_B"]
    pid_confirm = step4["PID_A"]
    pid_a = compute_pid(helper.identity_bytes, M_i_bytes)
    if pid_a != pid_confirm:
        raise ValueError("helper PID mismatch in step4 response")
    ts4 = int.from_bytes(step4["TS4"], "big")

    ue_cache = UEPreAuthCache(
        helper_id=helper.entity_id,
        target_id=authenticator.entity_id,
        target_domain_id=authenticator.domain.domain_id,
        ue_pid=pid_i,
        helper_pid=pid_a,
        helper_identity_bytes=helper.identity_bytes,
        m_i=m_i,
        M_i_bytes=M_i_bytes,
        h_target=h_B,
        pid_target=pid_target,
        M_target_bytes=M_B_bytes,
        ts1=ts1,
        ts4=ts4,
    )

    write_ue_cache(args.cache_dir, args.ue_id, ue_cache)
    sock.close()

    result = {
        "status": "ok",
        "stage": "completed",
        "ts1": ts1,
        "ts4": ts4,
    }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
