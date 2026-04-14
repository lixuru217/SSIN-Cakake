#!/usr/bin/env python3
"""Run an in-process Liu2022 access + handover demo without Docker."""

from __future__ import annotations

import binascii
import time
from pathlib import Path

from liu2022 import (
    HandoverRequest,
    HandoverResponse,
    decrypt_with_key,
    unpack_lka_payload,
)

from liu2022_context import load_context


def main() -> None:
    context_path = Path(__file__).resolve().parents[1] / "shared" / "offline_context_liu.pkl"
    context = load_context(context_path)

    gm = context.gm
    ap1 = context.aps["AP-01"]
    ap2 = context.aps["AP-02"]
    ue = context.ue_records["ue-001"].state

    now_ms = lambda: int(time.time() * 1000)

    def dump_assignment(prefix: str, ap_state) -> None:
        assignment = ap_state.assignments.get(ap_state.current_apgid)
        if assignment is None:
            print(prefix, "no active assignment")
            return
        print(
            prefix,
            {
                "apgid": assignment.apgid,
                "apgk_int": assignment.apgk_int,
                "sgk": assignment.sgk_bytes.hex(),
                "coeff": assignment.coefficients,
                "hac_targets": [cred.target_apgid for cred in assignment.hac],
                "hac_expiry": [cred.expiry_ts for cred in assignment.hac],
            },
        )

    def negotiate(ap, name: str):
        ts = now_ms()
        request = ap.start_group_request(ts)
        response = gm.process_group_request(request, now=ts + 5)
        print(
            f"[GM] response for {name}",
            {
                "apgid": response.apgid,
                "hac_targets": [cred.target_apgid for cred in response.hac],
                "hac_expiry": [cred.expiry_ts for cred in response.hac],
                "coeff": response.coefficients,
            },
        )
        ap.process_group_response(response, now=ts + 10)
        dump_assignment(f"[{name}] assignment after negotiate", ap)

    negotiate(ap1, "AP-01")
    negotiate(ap2, "AP-02")

    ts_access = now_ms()
    access_request = ue.create_access_request(ts_access)
    access_response = ap1.handle_access_request(access_request, now=ts_access + 10)
    ue_session = ue.process_access_response(access_response, now=ts_access + 20)
    print("Access status:", ue_session.apgid, "latency", access_response.ts2 - ts_access)
    print("Access response LKA count:", len(access_response.lka))
    for idx, ticket in enumerate(access_response.lka, start=1):
        print(
            f"  LKA[{idx}]",
            {
                "apgid": ticket.apgid,
                "nonce": ticket.nonce.hex(),
                "payload_len": len(ticket.encrypted_payload),
                "expiry": ticket.expiry_ts,
            },
        )

    assignment_ap2 = ap2.assignments.get(ap2.current_apgid)
    if assignment_ap2:
        sgk_ap2 = assignment_ap2.sgk_bytes
        ap1_ap2_cred = next(
            (cred for cred in ap1.assignments[ap1.current_apgid].hac if cred.target_apgid == assignment_ap2.apgid),
            None,
        )
        if ap1_ap2_cred:
            print("AP-01 credential for AP-02 sgk:", ap1_ap2_cred.sgk_bytes.hex())
        else:
            print("AP-01 credential for AP-02 not found in HAC")
        for ticket in access_response.lka:
            if ticket.apgid == assignment_ap2.apgid:
                try:
                    plaintext = decrypt_with_key(sgk_ap2, ticket.nonce, ticket.encrypted_payload)
                    print("  Decrypted LKA for AP-02:", plaintext.hex())
                    print("  Parsed:", unpack_lka_payload(plaintext))
                except Exception as exc:  # pylint: disable=broad-except
                    print("  Failed to decrypt LKA for AP-02:", exc)
    else:
        print("AP-02 has no assignment at access stage")

    ts_handover = ts_access + 50
    handover_request = ue.create_handover_request("AP-02", ts_handover)
    print(
        "Handover request summary",
        {
            "lka_count": len(handover_request.lka),
            "target_ap": handover_request.target_ap_id,
            "ts1": handover_request.ts1,
        },
    )
    try:
        handover_response = ap2.process_handover_request(handover_request, now=ts_handover + 5)
        ue.process_handover_response(handover_response, now=ts_handover + 10)
        print("Handover complete to", handover_response.ap_id)
    except Exception as exc:  # pylint: disable=broad-except
        print("Handover failed:", exc)


if __name__ == "__main__":
    main()
