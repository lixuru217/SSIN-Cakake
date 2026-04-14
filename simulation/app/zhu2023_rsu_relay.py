#!/usr/bin/env python3
"""Relay RSU (LEO1) server for Zhu2023 handover experiments."""

from __future__ import annotations

import argparse
import logging
import socket
from pathlib import Path

from metrics import Timer, sample_cpu
from zhu2023_codec import decode_payload, encode_switch_response, ensure_type

logger = logging.getLogger("zhu2023_rsu1")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Zhu2023 relay RSU server")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=6000, help="UDP port to listen on")
    parser.add_argument("--target-host", default="leo2", help="Target RSU hostname")
    parser.add_argument("--target-port", type=int, default=5000, help="Target RSU UDP port")
    parser.add_argument("--target-timeout", type=float, default=1.0, help="Seconds to wait for target response")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    parser.add_argument("--rsu-id", default="RSU-01", help="Identifier for this relay RSU")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[LEO1] %(message)s")

    inbound_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    inbound_sock.bind((args.bind, args.port))

    target_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target_sock.settimeout(max(0.1, args.target_timeout))

    logger.info("relay RSU ready on %s:%d", args.bind, args.port)

    while True:
        data, addr = inbound_sock.recvfrom(65535)
        try:
            payload = ensure_type(decode_payload(data), "switch_request")
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("discarding invalid request from %s: %s", addr, exc)
            error = encode_switch_response(
                {
                    "status": "failed",
                    "rsu_id": args.rsu_id,
                    "message": str(exc),
                }
            )
            inbound_sock.sendto(error, addr)
            continue

        cpu_before = sample_cpu()
        timer = Timer.start()
        try:
            target_sock.sendto(data, (args.target_host, args.target_port))
            response, _ = target_sock.recvfrom(65535)
        except socket.timeout:
            logger.error("timeout waiting for target RSU response")
            failure = encode_switch_response(
                {
                    "status": "failed",
                    "rsu_id": args.rsu_id,
                    "message": "target rsu timeout",
                }
            )
            inbound_sock.sendto(failure, addr)
            continue

        try:
            response_payload = ensure_type(decode_payload(response), "switch_response")
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("invalid response from target RSU: %s", exc)
            failure = encode_switch_response(
                {
                    "status": "failed",
                    "rsu_id": args.rsu_id,
                    "message": "malformed target response",
                }
            )
            inbound_sock.sendto(failure, addr)
            continue

        cpu_after = sample_cpu()
        metrics = response_payload.setdefault("metrics", {})
        metrics["cpu_ms_rsu1"] = max(0.0, cpu_after.to_ms() - cpu_before.to_ms())
        metrics["processing_ms_rsu1"] = timer.stop_ms()
        metrics["bytes_rsu1"] = float(metrics.get("bytes_rsu1", 0.0) + len(data) + len(response))
        metrics["msgs_rsu1"] = int(metrics.get("msgs_rsu1", 0) + 2)
        response_payload["metrics"] = metrics

        encoded = encode_switch_response(response_payload)
        inbound_sock.sendto(encoded, addr)
        logger.info("forwarded response to %s status=%s", addr, response_payload.get("status"))


if __name__ == "__main__":
    main()
