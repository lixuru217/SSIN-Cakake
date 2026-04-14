#!/usr/bin/env python3
"""Group manager server for the Liu2022 protocol."""

from __future__ import annotations

import argparse
import logging
import socket
import time
from pathlib import Path

from liu2022_codec import (
    decode_envelope,
    dict_to_group_request,
    encode_envelope,
    group_response_to_dict,
)
from liu2022_context import get_gm_state, load_context

logger = logging.getLogger("liu2022_gm")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Liu2022 GM server")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle path")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=8000, help="UDP port")
    parser.add_argument("--tolerance-ms", type=int, default=2000, help="Timestamp tolerance in ms")
    parser.add_argument("--validity-ms", type=int, default=10 * 60 * 1000, help="Group credential validity")
    parser.add_argument("--log-level", default="INFO")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[GM] %(message)s")

    context = load_context(args.context)
    gm_state = get_gm_state(context)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))

    logger.info("GM server listening on %s:%d", args.bind, args.port)

    while True:
        data, addr = sock.recvfrom(65535)
        try:
            payload = decode_envelope(data)
        except ValueError:
            logger.warning("invalid payload from %s", addr)
            continue

        if payload.get("type") != "group_request":
            logger.warning("unexpected message type=%s from %s", payload.get("type"), addr)
            continue

        now_ms = int(time.time() * 1000)
        try:
            request = dict_to_group_request(payload)
            response = gm_state.process_group_request(
                request,
                now=now_ms,
                tolerance_ms=args.tolerance_ms,
                validity_ms=args.validity_ms,
            )
            response_payload = group_response_to_dict(response)
            sock.sendto(encode_envelope(response_payload), addr)
            logger.info("processed group request from %s ap_id=%s", addr, request.ap_id)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("failed to process group request: %s", exc)
            error_payload = {
                "type": "error",
                "stage": "gm_group",
                "message": str(exc),
            }
            sock.sendto(encode_envelope(error_payload), addr)


if __name__ == "__main__":
    main()
