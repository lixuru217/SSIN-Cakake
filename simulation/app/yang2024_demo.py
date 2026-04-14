#!/usr/bin/env python3
"""Simple Yang2024 vehicular network simulation."""

from __future__ import annotations

import argparse
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "protocols"))

import yang2024  # type: ignore  # noqa: E402  pylint: disable=wrong-import-position


def _init_vehicle(ta: yang2024.TrustedAuthority, real_identity: str, validity_ts: int) -> yang2024.VehicleState:
    params = ta.public_parameters()
    vehicle = yang2024.VehicleState(real_identity, params)
    request = vehicle.create_pseudo_id_request(validity_ts)
    response = ta.issue_pseudo_identity(request)
    vehicle.receive_pseudo_identity(response)
    partial = ta.issue_partial_secret(vehicle.pseudo_identity)
    vehicle.install_partial_secret(partial)
    return vehicle


def _run_round(
    rsu: yang2024.RSUVerifier,
    app: yang2024.ApplicationServer,
    vehicles: Sequence[yang2024.VehicleState],
    *,
    timestamp: int,
    base_message: str,
    noisy: bool,
) -> int:
    broadcasts: List[yang2024.SignedBroadcast] = []
    for vehicle in vehicles:
        payload = f"{base_message}|veh={vehicle.real_identity}|ts={timestamp}".encode("utf-8")
        broadcast = vehicle.sign(payload, timestamp)
        broadcasts.append(broadcast)
        valid = rsu.verify(broadcast, now=timestamp + 100)
        if noisy:
            print(f"[RSU] verify veh={vehicle.real_identity} -> {valid}")
    aggregate = rsu.aggregate(broadcasts)
    verified = app.verify_aggregate(broadcasts, aggregate, now=timestamp + 100)
    if noisy:
        print(f"[APP] aggregate verified={verified}")
    return int(verified)


@dataclass
class SimulationResult:
    verified_ratio: float
    rounds: int
    total_broadcasts: int


def run_simulation(
    *,
    vehicle_count: int,
    rounds: int,
    start_timestamp: int,
    timestamp_step: int,
    verbose: bool,
) -> SimulationResult:
    ta = yang2024.TrustedAuthority()
    params = ta.public_parameters()
    vehicles = [
        _init_vehicle(ta, f"VEH-{idx:03d}", start_timestamp + 10_000)
        for idx in range(1, vehicle_count + 1)
    ]

    rsu = yang2024.RSUVerifier(params)
    app = yang2024.ApplicationServer(params)

    results = []
    for round_idx in range(rounds):
        ts = start_timestamp + round_idx * timestamp_step
        result = _run_round(
            rsu,
            app,
            vehicles,
            timestamp=ts,
            base_message=f"traffic:round={round_idx}",
            noisy=verbose,
        )
        results.append(result)
    return SimulationResult(
        verified_ratio=statistics.fmean(results) if results else 0.0,
        rounds=len(results),
        total_broadcasts=len(results) * vehicle_count,
    )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Yang2024 vehicular signing simulation.")
    parser.add_argument("--vehicles", type=int, default=5, help="Number of vehicles to simulate")
    parser.add_argument("--rounds", type=int, default=3, help="Number of signing rounds to perform")
    parser.add_argument("--start-ts", type=int, default=1_000_000, help="Starting timestamp (ms)")
    parser.add_argument("--ts-step", type=int, default=1_000, help="Timestamp delta per round (ms)")
    parser.add_argument("--verbose", action="store_true", help="Print per-round verification details")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    result = run_simulation(
        vehicle_count=args.vehicles,
        rounds=args.rounds,
        start_timestamp=args.start_ts,
        timestamp_step=args.ts_step,
        verbose=args.verbose,
    )
    print(
        "[SUMMARY]",
        {
            "rounds": result.rounds,
            "vehicles": args.vehicles,
            "total_broadcasts": result.total_broadcasts,
            "verified_ratio": f"{result.verified_ratio:.2f}",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
