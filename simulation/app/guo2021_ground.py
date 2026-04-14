#!/usr/bin/env python3
"""Ground station server for Guo2021 initial authentication (M2/M3)."""

from __future__ import annotations

import argparse
import logging
import socket
import time
from pathlib import Path

from metrics import sample_cpu, Timer

from guo2021 import GroundStationState
from guo2021_codec import decode_envelope, dict_to_m2, encode_envelope, m3_to_dict
from guo2021_context import get_identifiers, get_ground_state, load_context

logger = logging.getLogger("guo2021_ground")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Guo2021 ground station server")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle path")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=7000, help="UDP port")
    parser.add_argument("--sat-host", default="leo1", help="Old satellite host")
    parser.add_argument("--sat-port", type=int, default=6000, help="Old satellite UDP port")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--tolerance-inner", type=int, default=1200, help="Inner timestamp tolerance ms")
    parser.add_argument("--tolerance-outer", type=int, default=2000, help="Outer timestamp tolerance ms")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[GROUND] %(message)s")

    context = load_context(args.context)
    ground: GroundStationState = get_ground_state(context)
    _, _, ground_id = get_identifiers(context)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))

    logger.info("ground station listening on %s:%d", args.bind, args.port)

    while True:
        data, addr = sock.recvfrom(65535)
        try:
            payload = decode_envelope(data)
        except ValueError:
            logger.warning("malformed packet from %s", addr)
            continue

        if payload.get("type") != "m2":
            logger.warning("unexpected message type=%s from %s", payload.get("type"), addr)
            continue

        timer = Timer.start()
        cpu_before = sample_cpu()

        try:
            message_m2 = dict_to_m2(payload)
            response = ground.process_m2(
                message_m2,
                now=int(time.time() * 1000),
                tolerance_inner=args.tolerance_inner,
                tolerance_outer=args.tolerance_outer,
            )
            cpu_after = sample_cpu()
            metrics = {
                "cpu_ms_ground": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                "processing_ms_ground": timer.stop_ms(),
            }
            outbound = {"type": "m3"}
            outbound.update(m3_to_dict(response))
            outbound["metrics"] = metrics
            sock.sendto(encode_envelope(outbound), (args.sat_host, args.sat_port))
            logger.info("processed M2 tid=%s for ground %s", message_m2.tid, ground_id)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("failed to process M2: %s", exc)
            error_payload = {
                "type": "error",
                "tid": payload.get("tid", ""),
                "gs_id": ground_id,
                "stage": "ground_m2",
                "message": str(exc),
            }
            sock.sendto(encode_envelope(error_payload), (args.sat_host, args.sat_port))


if __name__ == "__main__":
    main()
