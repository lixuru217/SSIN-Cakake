#!/usr/bin/env python3
"""REN2023 UE client driving single handover attempts."""

from __future__ import annotations

import argparse
import json
import logging
import pickle
import socket
import sys
import time
from pathlib import Path
from typing import Dict, Tuple

from metrics import Timer, sample_cpu
from ren2023_codec import (
    decode_json,
    encode_json,
    handover_request_to_dict,
    ho_downlink_from_dict,
    stored_payload_to_dict,
    terminal_response_to_dict,
)
from ren2023_context import load_context

PROTOCOLS_PATH = Path(__file__).resolve().parents[2] / "protocols"
if str(PROTOCOLS_PATH) not in sys.path:
    sys.path.insert(0, str(PROTOCOLS_PATH))

import ren2023

DEFAULT_STATE_CACHE_PATH = Path("/tmp/ren2023_terminal_state.pkl")
logger = logging.getLogger("ren2023_ue_client")

STAGE_TER_TO_UAV_REQ = "ter_to_uav_request"
STAGE_TER_TO_UAV_FINAL = "ter_to_uav_terminal"

STAGE_TER_TO_UAV_REQ = "ter_to_uav_request"
STAGE_TER_TO_UAV_FINAL = "ter_to_uav_terminal"


def _context_signature(path: Path) -> int:
    try:
        return int(path.stat().st_mtime_ns)
    except FileNotFoundError:
        return 0


def _load_cached_terminal(cache_path: Path, signature: int) -> ren2023.Terminal | None:
    try:
        with cache_path.open("rb") as fh:
            payload = pickle.load(fh)
    except FileNotFoundError:
        return None
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("failed to load REN terminal cache %s: %s", cache_path, exc)
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("signature") != signature:
        return None
    terminal = payload.get("terminal")
    if not isinstance(terminal, ren2023.Terminal):
        return None
    return terminal


def _save_cached_terminal(cache_path: Path, signature: int, terminal: ren2023.Terminal) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"signature": signature, "terminal": terminal}
    tmp_path = cache_path.with_suffix(".tmp")
    with tmp_path.open("wb") as fh:
        pickle.dump(payload, fh)
    tmp_path.replace(cache_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="REN2023 UE handover client")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle")
    parser.add_argument("--ue-id", default="TER-01", help="Terminal identifier")
    parser.add_argument("--leo-host", default="ren_leo2", help="Target UAV host name")
    parser.add_argument("--leo-port", type=int, default=5000, help="Target UAV UDP port")
    parser.add_argument("--timeout-ms", type=int, required=True, help="Per-attempt timeout in milliseconds")
    parser.add_argument("--pto", type=int, default=0, help="Retry attempts (unused placeholder)")
    parser.add_argument("--log-json", type=Path, help="Optional JSON log output")
    parser.add_argument(
        "--state-cache",
        type=Path,
        default=DEFAULT_STATE_CACHE_PATH,
        help="Path to persist terminal handover state between runs",
    )
    return parser


def _write_result(record: Dict[str, object], log_path: Path | None) -> None:
    line = json.dumps(record, separators=(",", ":"))
    print(line, flush=True)
    if log_path is not None:
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


REMOTE_STAGE_KEYS = {
    "uav_to_ncc_request",
    "ncc_to_uav_response",
    "uav_to_ter_downlink",
    "uav_to_ncc_complete",
}


def _count_online_messages(local_counts: Dict[str, int], remote_counts: Dict[str, object]) -> int:
    total = int(local_counts.get(STAGE_TER_TO_UAV_REQ, 0)) + int(local_counts.get(STAGE_TER_TO_UAV_FINAL, 0))
    for key in REMOTE_STAGE_KEYS:
        try:
            total += int(remote_counts.get(key, 0))
        except (TypeError, ValueError):
            continue
    return total


def _pid_bytes_length(pid: str) -> int:
    try:
        return len(bytes.fromhex(pid))
    except ValueError:
        return len(pid.encode("utf-8"))


def _handover_request_payload_len(request: ren2023.TerminalHandoverRequest) -> int:
    return _pid_bytes_length(request.pid)


def _handover_ack_payload_len(
    response: ren2023.TerminalHandoverResponse,
    stored_payload: ren2023._StoredHandoverPayload | None,  # type: ignore[attr-defined]
) -> int:
    total = len(response.n_t) + len(response.auth_tnu) + len(response.r_masked)
    if stored_payload is not None:
        total += len(stored_payload.challenge_new)
        total += len(stored_payload.response_new)
        total += len(stored_payload.sk_tnu)
        total += _pid_bytes_length(stored_payload.pid_new)
    return total


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(level=logging.INFO, format="[REN-UE] %(message)s")
    context_sig = _context_signature(args.context)
    context = load_context(args.context)
    terminal = context.terminal
    cache_path = args.state_cache
    if cache_path is not None:
        cached_terminal = _load_cached_terminal(cache_path, context_sig)
        if cached_terminal is not None:
            terminal = cached_terminal
    def _persist_terminal_state() -> None:
        if cache_path is None:
            return
        try:
            _save_cached_terminal(cache_path, context_sig, terminal)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("failed to persist REN terminal state: %s", exc)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout_ms / 1000.0)

    attempt_sessions = max(1, args.pto + 1)

    def _run_session() -> Dict[str, object]:
        cpu_before = sample_cpu()
        timer = Timer.start()
        stage_counts_local = {STAGE_TER_TO_UAV_REQ: 0, STAGE_TER_TO_UAV_FINAL: 0}
        max_retries = max(1, args.pto + 1)
        bytes_total = 0.0

        def _attempts() -> int:
            return int(stage_counts_local.get(STAGE_TER_TO_UAV_REQ, 0))

        def _send_and_wait(
            payload_dict: Dict[str, object],
            stage_label: str,
            expected_type: str,
            timeout_stage: str,
            invalid_stage: str,
            business_len: int,
        ) -> Dict[str, object]:
            nonlocal bytes_total
            payload_bytes = encode_json(payload_dict)
            for retry_idx in range(max_retries):
                stage_counts_local[stage_label] += 1
                try:
                    sock.sendto(payload_bytes, (args.leo_host, args.leo_port))
                except OSError as exc:  # socket.gaierror, etc.
                    if retry_idx == max_retries - 1:
                        raise ConnectionError(f"{timeout_stage}_send_error") from exc
                    continue
                bytes_total += business_len
                try:
                    data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    if retry_idx == max_retries - 1:
                        raise TimeoutError(timeout_stage)
                    continue
                try:
                    response = decode_json(data)
                except Exception as exc:  # pylint: disable=broad-except
                    if retry_idx == max_retries - 1:
                        raise ValueError(invalid_stage) from exc
                    continue
                if expected_type and response.get("type") != expected_type:
                    if retry_idx == max_retries - 1:
                        raise ValueError(invalid_stage)
                    continue
                return response
            raise RuntimeError("unreachable")

        try:
            ho_request = terminal.start_handover()
        except Exception:
            cpu_after = sample_cpu()
            elapsed = timer.stop_ms()
            return {
                "status": "failed",
                "failed_stage": "start_handover",
                "errno": 0,
                "attempts": _attempts(),
                "timeout_ms": args.timeout_ms,
                "pto": args.pto,
                "latency_ms": elapsed,
                "cpu_ms_ue": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                "cpu_ms_leo2": 0.0,
                "cpu_ms_ground": 0.0,
                "msgs_online": 0,
                "bytes_online": 0.0,
            }

        ts5 = int(time.time() * 1000)
        packet = handover_request_to_dict(ho_request, ue_id=args.ue_id)
        packet["ts5"] = ts5

        try:
            response_dict = _send_and_wait(
                packet,
                stage_label=STAGE_TER_TO_UAV_REQ,
                expected_type="handover_downlink",
                timeout_stage="leo_timeout",
                invalid_stage="invalid_downlink",
                business_len=_handover_request_payload_len(ho_request),
            )
        except (TimeoutError, ValueError, ConnectionError) as exc:
            cpu_after = sample_cpu()
            elapsed = timer.stop_ms()
            return {
                "status": "failed",
                "failed_stage": str(exc),
                "errno": 0,
                "attempts": _attempts(),
                "timeout_ms": args.timeout_ms,
                "pto": args.pto,
                "latency_ms": elapsed,
                "cpu_ms_ue": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                "cpu_ms_leo2": 0.0,
                "cpu_ms_ground": 0.0,
                "msgs_online": _count_online_messages(stage_counts_local, {}),
                "bytes_online": float(bytes_total),
            }

        downlink = ho_downlink_from_dict(response_dict)
        remote_stage_counts = response_dict.get("stage_counts", {})

        try:
            term_response, _, _, _ = terminal.complete_handover(downlink)
        except Exception:
            cpu_after = sample_cpu()
            elapsed = timer.stop_ms()
            return {
                "status": "failed",
                "failed_stage": "complete_handover",
                "errno": 0,
                "attempts": _attempts(),
                "timeout_ms": args.timeout_ms,
                "pto": args.pto,
                "latency_ms": elapsed,
                "cpu_ms_ue": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                "cpu_ms_leo2": float(response_dict.get("metrics", {}).get("cpu_ms_leo2", 0.0)),
                "cpu_ms_ground": 0.0,
                "msgs_online": _count_online_messages(stage_counts_local, remote_stage_counts),
                "bytes_online": float(bytes_total),
            }

        ho_payload = ren2023._HANDOVER_INBOX.get(ho_request.pid)  # type: ignore[attr-defined]
        if ho_payload is None:
            cpu_after = sample_cpu()
            elapsed = timer.stop_ms()
            return {
                "status": "failed",
                "failed_stage": "handover_payload_missing",
                "errno": 0,
                "attempts": _attempts(),
                "timeout_ms": args.timeout_ms,
                "pto": args.pto,
                "latency_ms": elapsed,
                "cpu_ms_ue": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                "cpu_ms_leo2": float(response_dict.get("metrics", {}).get("cpu_ms_leo2", 0.0)),
                "cpu_ms_ground": 0.0,
                "msgs_online": _count_online_messages(stage_counts_local, remote_stage_counts),
                "bytes_online": float(bytes_total),
            }

        terminal_message = terminal_response_to_dict(ho_request.pid, term_response)
        terminal_message["handover_state"] = stored_payload_to_dict(ho_payload)
        ren2023._HANDOVER_INBOX.pop(ho_request.pid, None)  # type: ignore[attr-defined]

        ack_business_len = _handover_ack_payload_len(term_response, ho_payload)
        try:
            ack_payload = _send_and_wait(
                terminal_message,
                stage_label=STAGE_TER_TO_UAV_FINAL,
                expected_type="handover_ack",
                timeout_stage="ack_timeout",
                invalid_stage="ack_invalid",
                business_len=ack_business_len,
            )
        except (TimeoutError, ValueError, ConnectionError) as exc:
            cpu_after = sample_cpu()
            elapsed = timer.stop_ms()
            return {
                "status": "failed",
                "failed_stage": str(exc),
                "errno": 0,
                "attempts": _attempts(),
                "timeout_ms": args.timeout_ms,
                "pto": args.pto,
                "latency_ms": elapsed,
                "cpu_ms_ue": max(0.0, cpu_after.to_ms() - cpu_before.to_ms()),
                "cpu_ms_leo2": float(response_dict.get("metrics", {}).get("cpu_ms_leo2", 0.0)),
                "cpu_ms_ground": 0.0,
                "msgs_online": _count_online_messages(stage_counts_local, remote_stage_counts),
                "bytes_online": float(bytes_total),
            }

        cpu_after = sample_cpu()
        elapsed = timer.stop_ms()
        cpu_delta = max(0.0, cpu_after.to_ms() - cpu_before.to_ms())
        ack_metrics = ack_payload.get("metrics", {}) if isinstance(ack_payload, dict) else {}
        cpu_ms_leo2 = float(ack_metrics.get("cpu_ms_leo2", ack_metrics.get("cpu_ms", 0.0)))
        cpu_ms_ground = float(
            ack_metrics.get("cpu_ms_ground", ack_metrics.get("cpu_ms_ncc", 0.0))
        )
        remote_stage_counts = ack_payload.get("stage_counts", {}) if isinstance(ack_payload, dict) else {}
        msgs_online = _count_online_messages(stage_counts_local, remote_stage_counts)
        return {
            "status": ack_payload.get("status", "ok"),
            "attempts": _attempts(),
            "timeout_ms": args.timeout_ms,
            "pto": args.pto,
            "latency_ms": elapsed,
            "bytes_online": float(bytes_total),
            "msgs_online": msgs_online,
            "cpu_ms_ue": cpu_delta,
            "cpu_ms_leo2": cpu_ms_leo2,
            "cpu_ms_ground": cpu_ms_ground,
            "ts5": ts5,
            "ts6": int(time.time() * 1000),
        }

    final_record: Dict[str, object] | None = None
    for session_attempt in range(1, attempt_sessions + 1):
        result = _run_session()
        result["attempts"] = session_attempt
        final_record = result
        _persist_terminal_state()
        if result.get("status") == "ok":
            break

    assert final_record is not None
    _write_result(final_record, args.log_json)


if __name__ == "__main__":
    main()
