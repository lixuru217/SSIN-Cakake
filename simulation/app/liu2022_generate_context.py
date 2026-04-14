#!/usr/bin/env python3
"""Utility to generate Liu2022 offline context pickles for the simulator."""

from __future__ import annotations

import argparse
from pathlib import Path

from liu2022_context import generate_offline_context, save_context


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate Liu2022 offline context")
    parser.add_argument("--output", type=Path, required=True, help="Destination pickle path")
    parser.add_argument(
        "--ue-ids",
        nargs="+",
        default=["ue-001", "ue-002", "ue-003"],
        help="UE identifiers to include",
    )
    parser.add_argument(
        "--ap-ids",
        nargs="+",
        default=["AP-01", "AP-02"],
        help="Access point identifiers",
    )
    parser.add_argument("--gm-id", default="GM-01", help="Group manager identifier")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    context = generate_offline_context(
        args.ue_ids,
        ap_ids=args.ap_ids,
        gm_id=args.gm_id,
    )
    save_context(context, args.output)
    print(f"offline context stored at {args.output}")


if __name__ == "__main__":
    main()
