#!/usr/bin/env python3
"""Minimal harness exercising the SSINAuth protocol implementation."""

import time

from ssinauth import (
    authenticator_process_uplink,
    batch_verify,
    finalize_authentication,
    mutual_authentication,
    perform_offline_phase,
    prepare_uplink,
)


def main() -> None:
    now = int(time.time())
    context = perform_offline_phase(
        ["ue-001", "ue-002", "ue-003"], base_timestamp=now
    )

    single_result = mutual_authentication(
        context.ue_records["ue-001"].state,
        context.authenticator,
        ts5=now + 4,
        ts6=now + 5,
        tolerance=600,
        fresh_reference=now,
    )

    print("Single UE session key:", single_result.session_key.hex())
    print("Single UE shared point:", single_result.shared_point_bytes.hex())

    batch_ids = ["ue-002", "ue-003"]
    ts_base = now + 100
    uplinks = []
    for idx, ue_id in enumerate(batch_ids):
        uplinks.append(
            prepare_uplink(
                context.ue_records[ue_id].state,
                context.authenticator,
                ts5=ts_base + idx,
                tolerance=600,
                fresh_reference=ts_base,
            )
        )

    ok, rho, proof = batch_verify(
        context.authenticator,
        uplinks,
        epoch_id=b"epoch-001",
        sample_size=1,
        current_time=ts_base + 10,
        tolerance=600,
    )

    print("Batch verification:", ok)
    print("VRF rho:", rho.hex())
    print("VRF proof:", proof.hex())

    if ok:
        for idx, ue_id in enumerate(batch_ids):
            sb_cache = context.authenticator.incoming_sessions[ue_id]
            q_b, v2 = authenticator_process_uplink(
                context.authenticator,
                sb_cache,
                uplinks[idx],
                ts6=ts_base + 20 + idx,
                tolerance=600,
                fresh_reference=ts_base,
            )
            result = finalize_authentication(
                context.ue_records[ue_id].state,
                context.authenticator,
                uplinks[idx],
                q_b,
                v2,
                ts6=ts_base + 20 + idx,
                tolerance=600,
                fresh_reference=ts_base,
            )
            print(f"{ue_id} session key:", result.session_key.hex())
            print(f"{ue_id} shared point:", result.shared_point_bytes.hex())


if __name__ == "__main__":
    main()
