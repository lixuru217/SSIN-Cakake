#!/usr/bin/env python3
"""Target RSU (LEO2) server for Yang2024 handover experiments."""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import time
from pathlib import Path
from typing import Tuple

PROTOCOLS_PATH = Path(__file__).resolve().parents[2] / "protocols"
if str(PROTOCOLS_PATH) not in sys.path:
    sys.path.insert(0, str(PROTOCOLS_PATH))

import yang2024

from metrics import Timer, sample_cpu
from yang2024_codec import encode_switch_response, broadcast_from_dict, decode_payload, ensure_type
from yang2024_context import get_parameters, load_context


def _load_parameters(context_path: Path) -> Tuple[yang2024.PublicParameters, float]:
    context = load_context(context_path)
    params = get_parameters(context)
    mtime = context_path.stat().st_mtime_ns
    return params, float(mtime)

logger = logging.getLogger("yang2024_rsu2")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Yang2024 target RSU server")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=5000, help="UDP port to listen on")
    parser.add_argument("--rsu-id", default="RSU-02", help="Identifier for this RSU")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[LEO2] %(message)s")

    params, context_mtime = _load_parameters(args.context)
    verifier = yang2024.RSUVerifier(params)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    logger.info("target RSU listening on %s:%d", args.bind, args.port)

    while True:
        # Reload context if the on-disk file changed (ensures UE/RSU share keys)
        try:
            current_mtime = float(args.context.stat().st_mtime_ns)
            if current_mtime != context_mtime:
                params, context_mtime = _load_parameters(args.context)
                verifier = yang2024.RSUVerifier(params)
                logger.info("reloaded context (mtime updated)")
        except FileNotFoundError:
            logger.warning("context file %s missing; continuing with existing parameters", args.context)

        data, addr = sock.recvfrom(65535)
        try:
            payload = ensure_type(decode_payload(data), "switch_request")
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("invalid switch request from %s: %s", addr, exc)
            error = encode_switch_response(
                {
                    "status": "error",
                    "message": str(exc),
                    "rsu_id": args.rsu_id,
                    "metrics": {"bytes_leo2": 0.0, "msgs_leo2": 0},
                }
            )
            sock.sendto(error, addr)
            continue

        cpu_before = sample_cpu()
        timer = Timer.start()
        bytes_in = len(data)
        try:
            broadcast = broadcast_from_dict(payload["broadcast"])
            now_ms = int(time.time() * 1000)
            if now_ms > broadcast.pseudo_id.expiry_ts:
                raise ValueError(
                    f"pseudo identity expired (expiry={broadcast.pseudo_id.expiry_ts}, now={now_ms})"
                )
            if not verifier.verify(broadcast, now=now_ms):
                raise ValueError("signature verification failed")

            cpu_after = sample_cpu()
            elapsed = timer.stop_ms()
            metrics = {
                "cpu_ms_leo2": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                "processing_ms_leo2": elapsed,
                "bytes_leo2": float(bytes_in),
                "msgs_leo2": 1,
            }
            response_dict = {
                "status": "ok",
                "rsu_id": args.rsu_id,
                "ts_ack": now_ms,
                "metrics": metrics,
            }
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("handover processing failed: %s", exc)
            response_dict = {
                "status": "failed",
                "rsu_id": args.rsu_id,
                "message": str(exc),
                "metrics": {
                    "bytes_leo2": float(bytes_in),
                    "msgs_leo2": 1,
                },
            }

        metrics = response_dict.setdefault("metrics", {})
        metrics.setdefault("bytes_leo2", float(bytes_in))
        metrics.setdefault("msgs_leo2", 1)
        response_payload = encode_switch_response(response_dict)
        try:
            sock.sendto(response_payload, addr)
            logger.info(
                "processed switch request from %s, bytes_in=%d bytes_out=%d",
                addr,
                bytes_in,
                len(response_payload),
            )
        except PermissionError as exc:
            logger.warning("failed to send response to %s: %s", addr, exc)


if __name__ == "__main__":
    main()
