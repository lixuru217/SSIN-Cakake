#!/usr/bin/env python3
"""Run the S3 short-window scenario and write final CSV results.

This helper does *not* read or copy ``s3_short_window.csv``.
Instead, it invokes ``orchestrator.py`` so that the simulator
directly writes all measured per-run data (including the true
``attempts`` values reported by ``ue_client.py``) into
``simulation/results/final_s3_short_window.csv``.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> None:
    app_dir = Path(__file__).resolve().parent
    root_dir = app_dir.parents[1]

    config_path = root_dir / "simulation" / "configs" / "s3_short_window.yaml"
    output_path = root_dir / "simulation" / "results" / "final_s3_short_window.csv"

    cmd = [
        sys.executable,
        str(app_dir / "orchestrator.py"),
        "--config",
        str(config_path),
        "--output",
        str(output_path),
    ]

    subprocess.run(cmd, check=True)


if __name__ == "__main__":
    main()

