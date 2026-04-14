#!/usr/bin/env python3
"""Utility to generate Guo2021 offline context pickles for the simulator."""

from __future__ import annotations

import argparse
from pathlib import Path

from guo2021_context import generate_offline_context, save_context


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate Guo2021 offline context")
    parser.add_argument("--output", type=Path, required=True, help="Destination pickle path")
    parser.add_argument(
        "--ue-ids",
        nargs="+",
        default=["ue-001", "ue-002", "ue-003"],
        help="UE identifiers to include",
    )
    parser.add_argument("--old-sat-id", default="L-01", help="Current satellite identifier")
    parser.add_argument("--new-sat-id", default="L-02", help="Target satellite identifier")
    parser.add_argument("--ground-id", default="GS-01", help="Ground station identifier")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    context = generate_offline_context(
        args.ue_ids,
        old_satellite_id=args.old_sat_id,
        new_satellite_id=args.new_sat_id,
        ground_id=args.ground_id,
    )
    save_context(context, args.output)
    print(f"offline context stored at {args.output}")


if __name__ == "__main__":
    main()
