#!/usr/bin/env python3
"""Application server verifying Yang2024 aggregate signatures."""

from __future__ import annotations

import argparse
import logging
import socket
import sys
from pathlib import Path

PROTOCOLS_PATH = Path(__file__).resolve().parents[2] / "protocols"
if str(PROTOCOLS_PATH) not in sys.path:
    sys.path.insert(0, str(PROTOCOLS_PATH))

import yang2024

from metrics import Timer, sample_cpu
from yang2024_codec import (
    aggregate_from_dict,
    broadcast_from_dict,
    encode_aggregate_response,
    ensure_type,
    decode_payload,
)
from yang2024_context import get_parameters, load_context

logger = logging.getLogger("yang2024_app")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Yang2024 application server process")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle path")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=7000, help="UDP port to listen on")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[APP] %(message)s")

    context = load_context(args.context)
    params = get_parameters(context)
    app = yang2024.ApplicationServer(params)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    logger.info("application server ready on %s:%d", args.bind, args.port)

    while True:
        data, addr = sock.recvfrom(65535)
        try:
            payload = ensure_type(decode_payload(data), "aggregate_verify")
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("invalid request from %s: %s", addr, exc)
            error = encode_aggregate_response({"status": "error", "message": str(exc)})
            sock.sendto(error, addr)
            continue

        timer = Timer.start()
        cpu_before = sample_cpu()
        try:
            broadcasts = [broadcast_from_dict(item) for item in payload.get("broadcasts", [])]
            aggregate = aggregate_from_dict(payload["aggregate"])
            ok = app.verify_aggregate(broadcasts, aggregate, now=None)
            cpu_after = sample_cpu()
            response = encode_aggregate_response(
                {
                    "status": "ok" if ok else "invalid",
                    "verified": bool(ok),
                    "metrics": {
                        "cpu_ms_app": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                        "processing_ms_app": timer.stop_ms(),
                    },
                }
            )
            sock.sendto(response, addr)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("verification failed: %s", exc)
            error = encode_aggregate_response({"status": "error", "message": str(exc)})
            sock.sendto(error, addr)


if __name__ == "__main__":
    main()
