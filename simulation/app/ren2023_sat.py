#!/usr/bin/env python3
"""Satellite relay for REN2023 handover simulations."""

from __future__ import annotations

import argparse
import logging
import socket
import sys
from pathlib import Path
from typing import Dict, Tuple

from ren2023_codec import decode_json, encode_json

logger = logging.getLogger("ren2023_sat")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="REN2023 satellite relay")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address for LEO2 traffic")
    parser.add_argument("--port", type=int, default=5500, help="UDP port for LEO2 traffic")
    parser.add_argument("--ncc-host", default="ren_ncc", help="Upstream NCC host name")
    parser.add_argument("--ncc-port", type=int, default=6000, help="Upstream NCC UDP port")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    return parser


def _ensure_stage(payload: Dict[str, object], key: str) -> None:
    stage = payload.setdefault("stage_counts", {})
    if isinstance(stage, dict):
        stage[key] = int(stage.get(key, 0)) + 1


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[REN-SAT] %(message)s")

    ncc_addr = (args.ncc_host, args.ncc_port)
    sessions: Dict[str, Tuple[str, int]] = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    logger.info("Satellite relay listening on %s:%d -> NCC %s:%d", args.bind, args.port, *ncc_addr)

    while True:
        data, addr = sock.recvfrom(65535)
        try:
            payload = decode_json(data)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("invalid JSON from %s: %s", addr, exc)
            continue

        msg_type = payload.get("type")
        if msg_type in {"handover_uplink", "handover_terminal_response", "handover_complete"}:
            pid = str(payload.get("pid", ""))
            if not pid:
                logger.warning("missing pid in message from %s", addr)
                continue
            sessions[pid] = addr
            _ensure_stage(payload, "sat_to_ncc")
            sock.sendto(encode_json(payload), ncc_addr)
            logger.debug("forwarded %s pid=%s -> NCC", msg_type, pid)
        elif msg_type in {"handover_response", "handover_final_ack"}:
            pid = str(payload.get("pid", ""))
            dest = sessions.get(pid)
            if not dest:
                logger.warning("no session for pid=%s when relaying %s", pid, msg_type)
                continue
            _ensure_stage(payload, "sat_to_leo2")
            sock.sendto(encode_json(payload), dest)
            if msg_type == "handover_final_ack":
                sessions.pop(pid, None)
            logger.debug("forwarded %s pid=%s -> LEO2", msg_type, pid)
        else:
            logger.warning("unknown message type=%s from %s", msg_type, addr)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
