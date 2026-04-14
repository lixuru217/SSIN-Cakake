#!/usr/bin/env python3
"""Ground/NCC service for REN2023 handover simulations."""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import time
from pathlib import Path

from metrics import Timer, sample_cpu
from ren2023_codec import (
    decode_json,
    encode_json,
    handover_uplink_from_dict,
    ho_response_to_dict,
    stored_payload_from_dict,
)
from ren2023_context import load_context

PROTOCOLS_PATH = Path(__file__).resolve().parents[2] / "protocols"
if str(PROTOCOLS_PATH) not in sys.path:
    sys.path.insert(0, str(PROTOCOLS_PATH))

import ren2023

logger = logging.getLogger("ren2023_ground")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="REN2023 NCC handover server")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=6000, help="UDP port for LEO2 messages")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    return parser


def _reload_context(context_path: Path, last_mtime: float) -> tuple[ren2023.NCC, float]:
    try:
        mtime = float(context_path.stat().st_mtime_ns)
    except FileNotFoundError:
        logger.warning("context %s missing; retaining previous state", context_path)
        return None, last_mtime  # type: ignore[return-value]
    if mtime == last_mtime:
        return None, last_mtime  # type: ignore[return-value]
    context = load_context(context_path)
    logger.info("context reloaded (mtime=%d)", int(mtime))
    return context.ncc, mtime


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[REN-NCC] %(message)s")

    context = load_context(args.context)
    ncc = context.ncc
    context_mtime = float(args.context.stat().st_mtime_ns)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    logger.info("NCC listening on %s:%d", args.bind, args.port)

    while True:
        data, addr = sock.recvfrom(65535)

        new_state, context_mtime = _reload_context(args.context, context_mtime)
        if new_state is not None:
            ncc = new_state

        try:
            payload = decode_json(data)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("invalid JSON from %s: %s", addr, exc)
            continue

        msg_type = payload.get("type")
        if msg_type == "handover_uplink":
            uplink = handover_uplink_from_dict(payload)
            cpu_before = sample_cpu()
            timer = Timer.start()
            response = ncc.handle_handover_request(uplink)
            cpu_after = sample_cpu()
            elapsed = timer.stop_ms()

            if not isinstance(response, ren2023.NCCUAVHOResponse):
                error = {
                    "type": "handover_reject",
                    "message": "handover failed",
                }
                sock.sendto(encode_json(error), addr)
                logger.error("handover request rejected for pid=%s", uplink.pid)
                continue

            metrics = {
                "cpu_ms_ncc": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                "processing_ms_ncc": elapsed,
            }
            packet = ho_response_to_dict(response)
            packet["pid"] = uplink.pid
            packet["metrics"] = metrics
            packet["stage_counts"] = {"ncc_to_uav_response": 1}
            sock.sendto(encode_json(packet), addr)
            logger.info("handover response issued pid=%s", uplink.pid)
        elif msg_type == "handover_complete":
            pid = str(payload["pid"])
            state_dict = payload.get("handover_state")
            if not isinstance(state_dict, dict):
                logger.error("handover_complete missing state for pid=%s", pid)
                continue
            stored_payload = stored_payload_from_dict(state_dict)
            ren2023._HANDOVER_INBOX[pid] = stored_payload  # type: ignore[attr-defined]
            try:
                cpu_before = sample_cpu()
                timer = Timer.start()
                ncc.mark_handover_complete(pid)
                cpu_after = sample_cpu()
                elapsed = timer.stop_ms()
                reply = {
                    "type": "handover_final_ack",
                    "pid": pid,
                    "status": "ok",
                    "metrics": {
                        "cpu_ms_ncc": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                        "processing_ms_ncc": elapsed,
                    },
                    "stage_counts": {},
                }
                sock.sendto(encode_json(reply), addr)
                logger.info("handover complete pid=%s", pid)
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("mark_handover_complete failed for pid=%s: %s", pid, exc)
                error = {
                    "type": "handover_final_ack",
                    "pid": pid,
                    "status": "error",
                    "message": str(exc),
                    "stage_counts": {},
                }
                sock.sendto(encode_json(error), addr)
        else:
            logger.warning("unknown message type=%s from %s", msg_type, addr)


if __name__ == "__main__":
    main()
