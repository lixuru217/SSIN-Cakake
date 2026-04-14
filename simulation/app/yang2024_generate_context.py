#!/usr/bin/env python3
"""Generate Yang2024 offline context for the simulator."""

from __future__ import annotations

import argparse
from pathlib import Path

from yang2024_context import DEFAULT_VALIDITY_TS, generate_offline_context, save_context


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate Yang2024 offline context")
    parser.add_argument("--output", type=Path, required=True, help="Destination pickle path")
    parser.add_argument(
        "--vehicle-ids",
        nargs="+",
        default=["veh-001", "veh-002", "veh-003"],
        help="Vehicle identifiers to pre-provision",
    )
    parser.add_argument("--rsu1-id", default="RSU-01", help="Initial RSU identifier")
    parser.add_argument("--rsu2-id", default="RSU-02", help="Target RSU identifier")
    parser.add_argument("--app-id", default="APP-01", help="Application server identifier")
    parser.add_argument(
        "--validity-ts",
        type=int,
        default=DEFAULT_VALIDITY_TS,
        help="Pseudo identity expiry timestamp (ms since epoch-style, default effectively non-expiring)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    context = generate_offline_context(
        args.vehicle_ids,
        rsu_ids=(args.rsu1_id, args.rsu2_id),
        app_id=args.app_id,
        validity_ts=args.validity_ts,
    )
    save_context(context, args.output)
    print(f"offline context stored at {args.output}")


if __name__ == "__main__":
    main()
