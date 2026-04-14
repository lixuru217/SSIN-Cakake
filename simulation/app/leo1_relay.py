#!/usr/bin/env python3
"""LEO1 relay service handling SSINAuth pre-authentication messages."""

from __future__ import annotations

import argparse
import logging
import socket
import time
from pathlib import Path

from context_utils import load_offline_context
from handshake_codec import decode_secure_message, encode_secure_message, envelope_from_payload
from ssinauth import compute_pid, timestamp_to_bytes

logger = logging.getLogger("leo1_relay")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LEO1 pre-auth relay")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle path")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address for UE messages")
    parser.add_argument("--port", type=int, default=6000, help="UDP port for UE messages")
    parser.add_argument("--leo2-host", default="leo2", help="LEO2 host name")
    parser.add_argument("--leo2-port", type=int, default=5000, help="LEO2 UDP port")
    parser.add_argument("--cache-dir", type=Path, default=Path("/shared/preauth"))
    parser.add_argument("--log-level", default="INFO")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[LEO1] %(message)s")

    context = load_offline_context(args.context)
    helper = context.helper
    helper_channel = context.helper_auth_channel

    socket_ue = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket_ue.bind((args.bind, args.port))
    socket_ue.settimeout(1.0)

    logger.info("relay listening on %s:%d", args.bind, args.port)

    while True:
        try:
            data, addr = socket_ue.recvfrom(8192)
        except socket.timeout:
            continue

        payload = decode_secure_message(data)
        msg_type = payload.get("type")
        ue_id = payload.get("ue_id")
        if msg_type != "preauth_step1" or ue_id is None:
            logger.warning("unexpected message type=%s", msg_type)
            continue

        if ue_id not in context.ue_records:
            logger.error("unknown UE id %s", ue_id)
            continue

        ue_record = context.ue_records[ue_id]
        ue_channel = ue_record.channel
        envelope = envelope_from_payload(payload)
        step1 = ue_channel.decrypt(envelope)

        M_i_bytes = step1["M_i"]
        ts1 = int.from_bytes(step1["TS1"], "big")

        pid_a = compute_pid(helper.identity_bytes, M_i_bytes)
        ts2 = int(time.time() * 1000)
        step2_payload = {
            "h_i": step1["h_i"],
            "M_i": step1["M_i"],
            "PID_A": pid_a,
            "PID_i": step1["PID_i"],
            "TS2": timestamp_to_bytes(ts2),
        }

        envelope2 = helper_channel.encrypt(step2_payload)
        message2 = encode_secure_message("preauth_step2", ue_id, envelope2, ts2=ts2)
        socket_ue.sendto(message2, (args.leo2_host, args.leo2_port))

        logger.info("forwarded step2 to LEO2 ue=%s", ue_id)

        # Wait for Step3 from LEO2
        try:
            data3, addr3 = socket_ue.recvfrom(8192)
        except socket.timeout:
            logger.error("timeout waiting for step3 ue=%s", ue_id)
            continue

        payload3 = decode_secure_message(data3)
        if payload3.get("type") != "preauth_step3" or payload3.get("ue_id") != ue_id:
            logger.warning("unexpected step3 message")
            continue

        envelope3 = envelope_from_payload(payload3)
        step3 = helper_channel.decrypt(envelope3)

        ts4 = int(time.time() * 1000)
        step4_payload = {
            "h_B": step3["h_B"],
            "M_B": step3["M_B"],
            "PID_A": step3["PID_A"],
            "PID_B": step3["PID_B"],
            "TS4": timestamp_to_bytes(ts4),
        }
        envelope4 = ue_channel.encrypt(step4_payload)
        message4 = encode_secure_message("preauth_step4", ue_id, envelope4, ts4=ts4)
        socket_ue.sendto(message4, addr)

        logger.info("relayed step4 to UE ue=%s", ue_id)

if __name__ == "__main__":
    main()
