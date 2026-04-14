#!/usr/bin/env python3
"""LEO2 authenticator UDP server used in the network simulation."""

from __future__ import annotations

import argparse
import json
import logging
import socket
import time
from pathlib import Path

from bn254.ecp import generator
from context_utils import load_offline_context, load_sb_cache, write_sb_cache
from handshake_codec import (
    decode_secure_message,
    decode_uplink,
    encode_error_response,
    encode_secure_message,
    encode_success_response,
    envelope_from_payload,
)
from metrics import Timer, sample_cpu
from ssinauth import (
    SBPreAuthCache,
    UplinkRequest,
    authenticator_process_uplink,
    compute_pid,
    hash_to_bytes,
    point_to_bytes,
    random_scalar,
    scalar_to_bytes,
    timestamp_to_bytes,
    xor_bytes,
)

logger = logging.getLogger("leo2_server")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LEO2 SSINAuth authenticator server")
    parser.add_argument("--context", type=Path, required=True, help="Path to offline context pickle")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=5000, help="UDP port to listen on")
    parser.add_argument("--cache-dir", type=Path, default=Path("/shared/preauth"))
    parser.add_argument("--log-level", default="INFO", help="Python logging level")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="[LEO2] %(message)s")

    context = load_offline_context(args.context)
    authenticator = context.authenticator
    helper = context.helper
    helper_channel = context.helper_auth_channel

    cache_index: dict[str, SBPreAuthCache] = {}
    for ue_id, record in context.ue_records.items():
        canonical = record.state.canonical_id
        stored_cache = load_sb_cache(args.cache_dir, ue_id)
        if stored_cache:
            authenticator.incoming_sessions[record.state.entity_id] = stored_cache
            cache_index[canonical] = stored_cache
        else:
            existing = authenticator.incoming_sessions.get(record.state.entity_id)
            if existing:
                cache_index[canonical] = existing

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    logger.info("listening on %s:%d", args.bind, args.port)

    while True:
        data, addr = sock.recvfrom(8192)
        try:
            base_payload = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            logger.error("invalid JSON from %s", addr)
            continue

        msg_type = base_payload.get("type")
        if msg_type == "preauth_step2":
            handle_preauth_step2(
                base_payload,
                addr,
                context,
                authenticator,
                helper,
                helper_channel,
                cache_index,
                sock,
                args.cache_dir,
            )
            continue

        if msg_type != "uplink":
            logger.warning("unexpected message type=%s from %s", msg_type, addr)
            continue

        packet = base_payload
        cpu_before = sample_cpu()
        timer = Timer.start()
        try:
            qe = packet["q_i"]
            ve = packet["v1"]
            ue_canonical = packet["ue_id"]
            ts5 = int(packet["ts5"])
            if ue_canonical not in cache_index:
                raise KeyError(f"no preauth cache for {ue_canonical}")
            sb_cache = cache_index[ue_canonical]
            uplink = UplinkRequest(
                ue_canonical=ue_canonical,
                Q_bytes=bytes.fromhex(qe),
                V1=bytes.fromhex(ve),
                TS5=ts5,
                M_bytes=sb_cache.M_ue_bytes,
            )
            ts6 = int(time.time() * 1000)
            q_b, v2 = authenticator_process_uplink(
                authenticator,
                sb_cache,
                uplink,
                ts6=ts6,
                tolerance=1200,
                fresh_reference=uplink.TS5,
            )
            cpu_after = sample_cpu()
            cpu_ms = max(0.0, cpu_after.to_ms() - cpu_before.to_ms())
            processing_ms = timer.stop_ms()
            response = encode_success_response(
                ue_canonical,
                ts6,
                q_b,
                v2,
                cpu_ms=cpu_ms,
                processing_ms=processing_ms,
            )
            logger.info(
                "uplink ok ue=%s ts5=%d ts6=%d cpu_ms=%.3f processing_ms=%.3f",
                ue_canonical,
                uplink.TS5,
                ts6,
                cpu_ms,
                processing_ms,
            )
        except Exception as exc:  # pylint: disable=broad-except
            cpu_after = sample_cpu()
            cpu_ms = max(0.0, cpu_after.to_ms() - cpu_before.to_ms())
            response = encode_error_response(
                base_payload.get("ue_id", "unknown"),
                failed_stage="authenticator",
                message=str(exc),
            )
            logger.error("failed to process uplink from %s: %s", addr, exc)
        sock.sendto(response, addr)


def handle_preauth_step2(
    payload: dict,
    addr,
    context,
    authenticator,
    helper,
    helper_channel,
    cache_index,
    sock,
    cache_dir: Path,
) -> None:
    ue_id = payload.get("ue_id")
    if ue_id not in context.ue_records:
        logger.error("preauth from unknown UE id %s", ue_id)
        return

    envelope = envelope_from_payload(payload)
    step2 = helper_channel.decrypt(envelope)

    M_i_bytes = step2["M_i"]
    pid_i = step2["PID_i"]
    pid_a = step2["PID_A"]
    ts2 = int.from_bytes(step2["TS2"], "big")

    identity_bytes = xor_bytes(pid_i, hash_to_bytes(b"Hpid", M_i_bytes))
    ue_record = context.ue_records[ue_id]
    if identity_bytes != ue_record.state.identity_bytes:
        logger.error("identity mismatch during preauth ue=%s", ue_id)
        return

    canonical = ue_record.state.canonical_id

    m_B = random_scalar()
    M_B_point = m_B * generator()
    M_B_bytes = point_to_bytes(M_B_point)
    pid_b = compute_pid(authenticator.identity_bytes, M_B_bytes)
    ts3 = int(time.time() * 1000)

    sb_cache = SBPreAuthCache(
        ue_id=ue_record.state.entity_id,
        ue_domain_id=ue_record.state.domain.domain_id,
        ue_identity_bytes=identity_bytes,
        helper_identity_bytes=helper.identity_bytes,
        ue_pid=pid_i,
        helper_pid=pid_a,
        h_ue=ue_record.state.h,
        ue_pk_bytes=ue_record.state.pk_bytes,
        ue_P_bytes=ue_record.state.P_bytes,
        ue_domain_pub=ue_record.state.domain.public_point(),
        M_ue_bytes=M_i_bytes,
        m_B=m_B,
        M_B_bytes=M_B_bytes,
        ts2=ts2,
        ts3=ts3,
    )

    authenticator.incoming_sessions[ue_record.state.entity_id] = sb_cache
    cache_index[canonical] = sb_cache
    write_sb_cache(cache_dir, ue_id, sb_cache)

    step3_payload = {
        "h_B": scalar_to_bytes(authenticator.h),
        "M_B": M_B_bytes,
        "PID_A": pid_a,
        "PID_B": pid_b,
        "TS3": timestamp_to_bytes(ts3),
    }
    envelope3 = helper_channel.encrypt(step3_payload)
    message3 = encode_secure_message("preauth_step3", ue_id, envelope3, ts3=ts3)
    sock.sendto(message3, addr)
    logger.info("preauth updated cache ue=%s", canonical)


if __name__ == "__main__":
    main()
