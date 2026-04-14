#!/usr/bin/env python3
"""Generate REN2023 offline context for the containerised simulator."""

from __future__ import annotations

import argparse
from pathlib import Path

from ren2023_context import generate_offline_context, save_context


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate REN2023 offline context")
    parser.add_argument("--output", type=Path, required=True, help="Destination pickle path")
    parser.add_argument("--domain", default="ren2023.sim", help="Domain identifier for the NCC")
    parser.add_argument("--terminal-id", default="TER-01", help="Terminal identifier")
    parser.add_argument("--uav-old-id", default="LEO-01", help="Serving UAV identifier")
    parser.add_argument("--uav-new-id", default="LEO-02", help="Target UAV identifier")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    context = generate_offline_context(
        domain=args.domain,
        terminal_id=args.terminal_id,
        uav_old_id=args.uav_old_id,
        uav_new_id=args.uav_new_id,
    )
    save_context(context, args.output)
    print(f"offline context stored at {args.output}")


if __name__ == "__main__":
    main()
