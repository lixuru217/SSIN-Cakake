#!/usr/bin/env python3
"""Regression tests for the Yang2024 vehicular signing protocol."""

from __future__ import annotations

import sys
from pathlib import Path

PROTOCOLS_PATH = Path(__file__).resolve().parents[1] / "protocols"
if str(PROTOCOLS_PATH) not in sys.path:
    sys.path.insert(0, str(PROTOCOLS_PATH))

import yang2024  # type: ignore  # pylint: disable=import-error


def _bootstrap_vehicle(
    ta: yang2024.TrustedAuthority,
    vehicle_id: str,
    validity_ts: int,
) -> yang2024.VehicleState:
    params = ta.public_parameters()
    vehicle = yang2024.VehicleState(vehicle_id, params)
    request = vehicle.create_pseudo_id_request(validity_ts)
    response = ta.issue_pseudo_identity(request)
    vehicle.receive_pseudo_identity(response)
    partial = ta.issue_partial_secret(vehicle.pseudo_identity)
    vehicle.install_partial_secret(partial)
    return vehicle


def test_single_signature_verification_succeeds() -> None:
    ta = yang2024.TrustedAuthority()
    params = ta.public_parameters()
    vehicle = _bootstrap_vehicle(ta, "VEH-100", validity_ts=1_000_000)

    timestamp = 900_000
    payload = b"traffic event"

    broadcast = vehicle.sign(payload, timestamp)
    rsu = yang2024.RSUVerifier(params)
    assert rsu.verify(broadcast, now=timestamp + 100)


def test_aggregate_verification_accepts_valid_bundle() -> None:
    ta = yang2024.TrustedAuthority()
    params = ta.public_parameters()
    vehicle_a = _bootstrap_vehicle(ta, "VEH-A", validity_ts=1_000_000)
    vehicle_b = _bootstrap_vehicle(ta, "VEH-B", validity_ts=1_000_000)

    timestamp = 900_500
    broadcast_a = vehicle_a.sign(b"speed:60", timestamp)
    broadcast_b = vehicle_b.sign(b"speed:58", timestamp)

    rsu = yang2024.RSUVerifier(params)
    assert rsu.verify(broadcast_a, now=timestamp + 50)
    assert rsu.verify(broadcast_b, now=timestamp + 50)

    aggregate = rsu.aggregate([broadcast_a, broadcast_b])
    app = yang2024.ApplicationServer(params)
    assert app.verify_aggregate([broadcast_a, broadcast_b], aggregate, now=timestamp + 90)


def test_aggregate_verification_rejects_tampering() -> None:
    ta = yang2024.TrustedAuthority()
    params = ta.public_parameters()
    vehicle_a = _bootstrap_vehicle(ta, "VEH-A", validity_ts=1_000_000)
    vehicle_b = _bootstrap_vehicle(ta, "VEH-B", validity_ts=1_000_000)

    timestamp = 920_000
    broadcast_a = vehicle_a.sign(b"payload-a", timestamp)
    broadcast_b = vehicle_b.sign(b"payload-b", timestamp)

    rsu = yang2024.RSUVerifier(params)
    aggregate = rsu.aggregate([broadcast_a, broadcast_b])

    tampered_point = bytearray(aggregate.aggregate_point)
    tampered_point[0] ^= 0x01
    tampered = yang2024.AggregateSignature(
        aggregate_point=bytes(tampered_point),
        delta=aggregate.delta,
        signature_count=aggregate.signature_count,
    )
    app = yang2024.ApplicationServer(params)
    assert not app.verify_aggregate([broadcast_a, broadcast_b], tampered, now=timestamp + 50)


def test_aggregate_verification_rejects_delta_tampering() -> None:
    ta = yang2024.TrustedAuthority()
    params = ta.public_parameters()
    vehicle_a = _bootstrap_vehicle(ta, "VEH-A", validity_ts=1_000_000)
    vehicle_b = _bootstrap_vehicle(ta, "VEH-B", validity_ts=1_000_000)

    timestamp = 930_000
    broadcast_a = vehicle_a.sign(b"delta-check-a", timestamp)
    broadcast_b = vehicle_b.sign(b"delta-check-b", timestamp)

    rsu = yang2024.RSUVerifier(params)
    aggregate = rsu.aggregate([broadcast_a, broadcast_b])
    tampered = yang2024.AggregateSignature(
        aggregate_point=aggregate.aggregate_point,
        delta=yang2024.normalize_scalar(aggregate.delta + 1),
        signature_count=aggregate.signature_count,
    )
    app = yang2024.ApplicationServer(params)
    assert not app.verify_aggregate([broadcast_a, broadcast_b], tampered, now=timestamp + 50)


def test_trace_operation_recovers_real_identity() -> None:
    ta = yang2024.TrustedAuthority()
    vehicle = _bootstrap_vehicle(ta, "VEH-TRACE", validity_ts=1_000_000)
    broadcast = vehicle.sign(b"status", timestamp=990_000)

    recovered = ta.trace_vehicle(broadcast.pseudo_id)
    assert recovered == "VEH-TRACE"
