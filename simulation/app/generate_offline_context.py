#!/usr/bin/env python3
"""Utility to generate and persist the SSINAuth offline context."""

from __future__ import annotations

import argparse
import pickle
from pathlib import Path
from typing import List

from ssinauth import OfflineContext, perform_offline_phase


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate offline SSINAuth context file")
    parser.add_argument("--output", type=Path, required=True, help="Destination pickle path")
    parser.add_argument(
        "--ue-ids",
        nargs="+",
        default=["ue-001", "ue-002", "ue-003"],
        help="UE identifiers to include in the context",
    )
    parser.add_argument("--base-timestamp", type=int, default=1, help="Starting timestamp seed")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    context: OfflineContext = perform_offline_phase(
        args.ue_ids,
        base_timestamp=args.base_timestamp,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as fh:
        pickle.dump(context, fh)
    print(f"offline context stored at {args.output}")


if __name__ == "__main__":
    main()

