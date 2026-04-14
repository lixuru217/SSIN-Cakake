#!/usr/bin/env python3
"""Access point server for the Liu2022 protocol."""

from __future__ import annotations

import argparse
import logging
import socket
import time
from pathlib import Path

from metrics import Timer, sample_cpu

from liu2022_codec import (
    access_request_to_dict,
    access_response_to_dict,
    decode_envelope,
    dict_to_access_request,
    dict_to_group_response,
    dict_to_handover_request,
    encode_envelope,
    group_request_to_dict,
    handover_response_to_dict,
)
from liu2022_context import get_ap_state, load_context
from liu2022_shared_store import BlindFactorStore

logger = logging.getLogger("liu2022_ap")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Liu2022 AP server")
    parser.add_argument("--context", type=Path, required=True, help="Offline context pickle path")
    parser.add_argument("--ap-id", required=True, help="Access point identifier")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=6000, help="UDP port for UE requests")
    parser.add_argument("--gm-host", default="gm", help="Group manager host")
    parser.add_argument("--gm-port", type=int, default=8000, help="Group manager UDP port")
    parser.add_argument("--gm-timeout-ms", type=int, default=2000, help="Timeout waiting for GM response")
    parser.add_argument("--tolerance-ms", type=int, default=2000, help="Timestamp tolerance in ms")
    parser.add_argument(
        "--blind-store",
        type=Path,
        default=Path("/shared/runtime/liu_blind_store.pkl"),
        help="Shared blind-factor store path",
    )
    parser.add_argument("--log-level", default="INFO")
    return parser


def negotiate_group(
    ap_state,
    *,
    gm_host: str,
    gm_port: int,
    timeout_ms: int,
    tolerance_ms: int,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(max(0.5, timeout_ms / 1000.0))

    ts1 = int(time.time() * 1000)
    request = ap_state.start_group_request(ts1)
    payload = group_request_to_dict(request)
    sock.sendto(encode_envelope(payload), (gm_host, gm_port))

    data, _ = sock.recvfrom(65535)
    response_payload = decode_envelope(data)
    if response_payload.get("type") != "group_response":
        raise RuntimeError(f"unexpected GM response: {response_payload}")
    response = dict_to_group_response(response_payload)
    ap_state.process_group_response(response, now=int(time.time() * 1000), tolerance_ms=tolerance_ms)
    logger.info("obtained group assignment apgid=%s", response.apgid)


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[AP %s] %%(message)s" % args.ap_id)

    context = load_context(args.context)
    ap_state = get_ap_state(context, args.ap_id)
    blind_store = BlindFactorStore(args.blind_store)

    # Preload any shared blind factors and patch NCC accessors so all APs stay in sync.
    shared_blinds = blind_store.snapshot()
    for idx, value in shared_blinds.items():
        ap_state.ncc.blind_factors.setdefault(idx, value)

    original_allocate = ap_state.ncc.allocate_blind_factor
    original_get = ap_state.ncc.get_blind_factor

    def allocate_shared(length: int):
        index, value = original_allocate(length)
        blind_store.write(index, value)
        logger.debug("stored blind factor index=%s length=%s", index, len(value))
        return index, value

    def get_shared(index: int):
        value = blind_store.read(index)
        if value is not None:
            ap_state.ncc.blind_factors[index] = value
            logger.debug("loaded blind factor index=%s length=%s (from store)", index, len(value))
            return value
        return original_get(index)

    ap_state.ncc.allocate_blind_factor = allocate_shared  # type: ignore[assignment]
    ap_state.ncc.get_blind_factor = get_shared  # type: ignore[assignment]

    logger.info("starting group negotiation with GM %s:%d", args.gm_host, args.gm_port)
    negotiate_group(
        ap_state,
        gm_host=args.gm_host,
        gm_port=args.gm_port,
        timeout_ms=args.gm_timeout_ms,
        tolerance_ms=args.tolerance_ms,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    logger.info("AP %s listening on %s:%d", args.ap_id, args.bind, args.port)

    while True:
        data, addr = sock.recvfrom(65535)
        try:
            payload = decode_envelope(data)
        except ValueError:
            logger.warning("invalid payload from %s", addr)
            continue

        msg_type = payload.get("type")
        now_ms = int(time.time() * 1000)
        cpu_before = sample_cpu()
        timer = Timer.start()

        try:
            if msg_type == "access_request":
                request = dict_to_access_request(payload)
                response = ap_state.handle_access_request(
                    request,
                    now=now_ms,
                    tolerance_ms=args.tolerance_ms,
                )
                response_payload = access_response_to_dict(response)
                metrics = {
                    "cpu_ms": max(0.0, sample_cpu().to_ms() - cpu_before.to_ms()),
                    "processing_ms": timer.stop_ms(),
                }
                response_payload["metrics"] = metrics
                sock.sendto(encode_envelope(response_payload), addr)
                logger.info("processed access request from %s", addr)
            elif msg_type == "handover_request":
                request = dict_to_handover_request(payload)
                logger.debug(
                    "handover request from %s: index_id=%s p_id=%s lka=%s",
                    addr,
                    request.index_id,
                    request.p_id.hex(),
                    [ticket.apgid for ticket in request.lka],
                )
                response = ap_state.process_handover_request(
                    request,
                    now=now_ms,
                    tolerance_ms=args.tolerance_ms,
                )
                response_payload = handover_response_to_dict(response)
                metrics = {
                    "cpu_ms": max(0.0, sample_cpu().to_ms() - cpu_before.to_ms()),
                    "processing_ms": timer.stop_ms(),
                }
                response_payload["metrics"] = metrics
                sock.sendto(encode_envelope(response_payload), addr)
                logger.info("processed handover request from %s", addr)
            else:
                logger.warning("unexpected message type=%s from %s", msg_type, addr)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("failed to handle %s: %s", msg_type, exc)
            error_payload = {
                "type": "error",
                "stage": msg_type or "ap_error",
                "message": str(exc),
            }
            sock.sendto(encode_envelope(error_payload), addr)


if __name__ == "__main__":
    main()
