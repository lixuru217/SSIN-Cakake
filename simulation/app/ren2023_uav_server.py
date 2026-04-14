#!/usr/bin/env python3
"""REN2023 target UAV (LEO2) server relaying handover messages."""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from metrics import Timer, sample_cpu
from ren2023_codec import (
    decode_json,
    encode_json,
    handover_request_from_dict,
    handover_request_to_dict,
    handover_uplink_to_dict,
    ho_downlink_to_dict,
    ho_response_from_dict,
    terminal_response_from_dict,
    terminal_response_to_dict,
)
from ren2023_context import load_context

PROTOCOLS_PATH = Path(__file__).resolve().parents[2] / "protocols"
if str(PROTOCOLS_PATH) not in sys.path:
    sys.path.insert(0, str(PROTOCOLS_PATH))

import ren2023

logger = logging.getLogger("ren2023_leo2")


def _send_json(
    sock: socket.socket,
    payload: Dict[str, Any],
    addr: Tuple[str, int],
    *,
    label: str,
    on_error: Optional[Callable[[], None]] = None,
) -> bool:
    try:
        sock.sendto(encode_json(payload), addr)
        return True
    except OSError as exc:
        logger.error("send failure [%s] to %s:%s - %s", label, addr[0], addr[1], exc)
        if on_error:
            try:
                on_error()
            except Exception as err:  # pragma: no cover - defensive
                logger.debug("on_error handler raised %s", err, exc_info=False)
        return False


def _merge_stage_counts(target: Dict[str, int], updates: Dict[str, Any]) -> None:
    for key, value in updates.items():
        try:
            inc = int(value)
        except (TypeError, ValueError):
            continue
        target[key] += inc


@dataclass
class PendingSession:
    ue_addr: Tuple[str, int]
    ncc_addr: Tuple[str, int]
    nu: bytes
    ts_start: float
    leo_metrics: Dict[str, float]
    stage_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    terminal_response: Optional[ren2023.TerminalHandoverResponse] = None
    ho_state: Optional[Dict[str, Any]] = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="REN2023 target UAV server")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address for UE messages")
    parser.add_argument("--port", type=int, default=5000, help="UDP port for UE messages")
    parser.add_argument("--ncc-host", default="ren_ground", help="Ground/NCC host name")
    parser.add_argument("--ncc-port", type=int, default=6000, help="Ground/NCC UDP port")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[REN-LEO2] %(message)s")

    context = load_context(args.context)
    leo2 = context.uav_new
    ncc_addr = (args.ncc_host, args.ncc_port)
    context_mtime = float(args.context.stat().st_mtime_ns)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    sock.settimeout(1.0)
    logger.info("LEO2 listening on %s:%d", args.bind, args.port)

    pending: Dict[str, PendingSession] = {}
    metrics_latest = defaultdict(float)

    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue

        try:
            current_mtime = float(args.context.stat().st_mtime_ns)
            if current_mtime != context_mtime:
                logger.info("context reload triggered")
                context = load_context(args.context)
                leo2 = context.uav_new
                context_mtime = current_mtime
                pending.clear()
        except FileNotFoundError:
            logger.warning("context %s missing; continuing with existing state", args.context)

        try:
            payload = decode_json(data)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("invalid JSON from %s: %s", addr, exc)
            continue

        msg_type = payload.get("type")
        if msg_type == "handover_request":
            request = handover_request_from_dict(payload)
            cpu_before = sample_cpu()
            timer = Timer.start()
            uplink = leo2.receive_handover_request(request)
            cpu_after = sample_cpu()
            elapsed = timer.stop_ms()

            metrics = {
                "cpu_ms_leo2": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                "processing_ms_leo2": elapsed,
            }

            pending[request.pid] = PendingSession(
                ue_addr=addr,
                ncc_addr=ncc_addr,
                nu=uplink.nu,
                ts_start=time.time(),
                leo_metrics=metrics,
                stage_counts=defaultdict(int),
            )
            pending[request.pid].stage_counts["uav_to_ncc_request"] += 1
            packet = handover_uplink_to_dict(uplink)
            packet["metrics"] = metrics
            packet["pid"] = request.pid

            if _send_json(
                sock,
                packet,
                ncc_addr,
                label=f"uplink pid={uplink.pid}",
                on_error=lambda: pending.pop(request.pid, None),
            ):
                logger.info("forwarded handover uplink pid=%s -> NCC", uplink.pid)

        elif msg_type == "handover_response":
            response = ho_response_from_dict(payload)
            session_pid = str(payload.get("pid", "")) or None
            if session_pid is None or session_pid not in pending:
                for pid_candidate, session in pending.items():
                    if session.ncc_addr == addr:
                        session_pid = pid_candidate
                        break
            if session_pid is None or session_pid not in pending:
                logger.warning("received NCC response with no pending session")
                continue

            session = pending[session_pid]
            _merge_stage_counts(session.stage_counts, payload.get("stage_counts", {}))
            cpu_before = sample_cpu()
            timer = Timer.start()
            downlink = leo2.process_handover_response(session_pid, response)
            cpu_after = sample_cpu()
            elapsed = timer.stop_ms()

            session.leo_metrics = {
                "cpu_ms_leo2": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                "processing_ms_leo2": elapsed,
            }

            session.stage_counts["uav_to_ter_downlink"] += 1
            packet = ho_downlink_to_dict(downlink)
            packet["stage_counts"] = dict(session.stage_counts)
            packet["metrics"] = session.leo_metrics
            packet["pid"] = session_pid
            if _send_json(sock, packet, session.ue_addr, label=f"downlink pid={session_pid}"):
                logger.info("delivered handover downlink pid=%s -> UE", session_pid)
            else:
                pending.pop(session_pid, None)

        elif msg_type == "handover_terminal_response":
            pid = str(payload["pid"])
            if pid not in pending:
                logger.warning("terminal response for unknown pid=%s", pid)
                continue
            session = pending[pid]
            terminal_response = terminal_response_from_dict(payload)
            state_dict = payload.get("handover_state")
            if not isinstance(state_dict, dict):
                logger.warning("handover_state missing for pid=%s", pid)
                continue

            try:
                cpu_before = sample_cpu()
                timer = Timer.start()
                leo2.finalise_handover(pid, terminal_response)
                cpu_after = sample_cpu()
                elapsed = timer.stop_ms()
                session.leo_metrics = {
                    "cpu_ms_leo2": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                    "processing_ms_leo2": elapsed,
                }
            except ValueError as exc:
                logger.error("finalise_handover failed for pid=%s: %s", pid, exc)
                error_pkt = {
                    "type": "handover_ack",
                    "status": "error",
                    "message": str(exc),
                    "pid": pid,
                    "stage_counts": dict(session.stage_counts),
                    "metrics": session.leo_metrics,
                }
                _send_json(sock, error_pkt, session.ue_addr, label=f"handover_error pid={pid}")
                pending.pop(pid, None)
                continue

            session.terminal_response = terminal_response
            session.ho_state = state_dict

            session.stage_counts["uav_to_ncc_complete"] += 1
            final_packet = {
                "type": "handover_complete",
                "pid": pid,
                "terminal_response": terminal_response_to_dict(pid, terminal_response),
                "handover_state": state_dict,
            }
            if _send_json(sock, final_packet, session.ncc_addr, label=f"complete pid={pid}"):
                logger.info("forwarded terminal response pid=%s -> NCC", pid)
            else:
                pending.pop(pid, None)

        elif msg_type == "handover_final_ack":
            pid = str(payload.get("pid", ""))
            if pid not in pending:
                logger.info("received NCC ack for unknown pid=%s", pid)
                continue
            session = pending.pop(pid)
            metrics = session.leo_metrics.copy()
            ground_metrics = payload.get("metrics", {})
            if isinstance(ground_metrics, dict):
                metrics.setdefault("cpu_ms_ground", ground_metrics.get("cpu_ms_ncc", 0.0))
                metrics.setdefault("processing_ms_ground", ground_metrics.get("processing_ms_ncc", 0.0))
            _merge_stage_counts(session.stage_counts, payload.get("stage_counts", {}))
            ack = {
                "type": "handover_ack",
                "status": payload.get("status", "ok"),
                "metrics": metrics,
                "stage_counts": dict(session.stage_counts),
            }
            _send_json(sock, ack, session.ue_addr, label=f"ack pid={pid}")
            logger.info("handover complete pid=%s (ack relayed)", pid)
        else:
            logger.warning("unrecognised message %s from %s", msg_type, addr)


if __name__ == "__main__":
    main()
