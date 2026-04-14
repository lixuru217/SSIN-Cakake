#!/usr/bin/env python3
"""Integration-style regression tests for REN2023 scenario simulations."""

from __future__ import annotations

import csv
import math
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ORCH_PATH = PROJECT_ROOT / "simulation" / "app"
if str(ORCH_PATH) not in sys.path:
    sys.path.insert(0, str(ORCH_PATH))

import ren2023_orchestrator as ren_orch

REN_DOCKER_TESTS = os.getenv("REN_DOCKER_TESTS") == "1"

SCENARIO_FILES = [
    ("ren_online_only", "simulation/configs/ren_online_only.yaml"),
    ("ren_rain_fade", "simulation/configs/ren_rain_fade.yaml"),
    ("ren_short_window", "simulation/configs/ren_short_window.yaml"),
]

EXPECTED_HEADER = ren_orch.FIELDNAMES


@pytest.mark.skipif(not REN_DOCKER_TESTS, reason="REN2023 Docker harness requires running containers")
@pytest.mark.parametrize("scenario_name, config_path", SCENARIO_FILES)
def test_ren2023_simulated_runs(tmp_path: Path, scenario_name: str, config_path: str) -> None:
    """Run the orchestrator in-process to ensure each scenario completes successfully."""
    config_file = Path(config_path)
    assert config_file.exists()

    output_path = tmp_path / f"{scenario_name}.csv"
    results, summary = ren_orch.run_scenario(config_file, output_path, runs_override=3)

    # Validate summary structure mirrors the reference protocols.
    assert summary["scenario"] == scenario_name
    assert 0 < summary["success_rate_online"] <= 1.0
    assert summary["cpu_ms_ue"] >= 0.0
    assert summary["cpu_ms_leo2"] >= 0.0
    assert summary["cpu_ms_ground"] >= 0.0
    assert summary["cpu_ms_ncc"] >= 0.0

    # CSV should exist and contain expected header.
    assert output_path.exists()
    with output_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == EXPECTED_HEADER
        rows = list(reader)
    assert rows, "orchestrator must yield at least one result row"

    for row in rows:
        assert row["status"] == "ok"
        assert row["failed_stage"] == ""
        for cpu_field in ("cpu_ms_ue", "cpu_ms_leo2", "cpu_ms_ground", "cpu_ms_ncc"):
            assert float(row[cpu_field]) >= 0.0
        assert int(row["msgs_online"]) >= 5
        assert float(row["latency_ms"]) > 0.0
        assert float(row["bytes_online"]) > 0.0
        loss_parts = [float(part) for part in str(row["loss_pct"]).split("/")]
        assert all(part >= 0.0 for part in loss_parts)

    with config_file.open("r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh)

    timeouts_count = len(config.get("timeouts_ms", []))
    pto_count = len(config.get("pto", []))
    base_multiplier = timeouts_count * pto_count * 3  # runs_override
    assert len(results) % base_multiplier == 0
    combo_count = len(results) // base_multiplier
    combo_indices = {int(row["combo_index"]) for row in rows}
    assert len(combo_indices) == combo_count

    def _count_list(value) -> int:
        if isinstance(value, list):
            return len(value)
        return 1

    if scenario_name == "ren_online_only":
        link_counts = []
        for link in ("ter_uavnew", "uavnew_sat", "sat_ncc"):
            link_cfg = config["links"][link]
            count = (
                _count_list(link_cfg.get("rtt_ms", 0.0))
                * _count_list(link_cfg.get("jitter_ms", 0.0))
                * _count_list(link_cfg.get("loss_pct", 0.0))
            )
            link_counts.append(count)
        expected_combos = link_counts[0] * link_counts[1] * link_counts[2]
    elif scenario_name == "ren_rain_fade":
        def _listify(value) -> List[float]:
            if isinstance(value, (list, tuple)):
                return [float(v) for v in value]
            if value is None:
                return [0.0]
            return [float(value)]

        def _rain_cfg(link: str) -> Dict[str, Any]:
            link_cfg = config["links"][link]
            states = link_cfg.get("states", {})
            assert states, f"{link} must define rain-fade states"
            return link_cfg

        def _count_rain(link: str) -> int:
            link_cfg = _rain_cfg(link)
            return _count_list(link_cfg.get("base_rtt_ms", link_cfg.get("rtt_ms", 0.0))) * len(link_cfg["states"])

        sat_cfg = config["links"]["sat_ncc"]
        sat_count = (
            _count_list(sat_cfg.get("rtt_ms", 0.0))
            * _count_list(sat_cfg.get("jitter_ms", 0.0))
            * _count_list(sat_cfg.get("loss_pct", 0.0))
        )
        expected_combos = _count_rain("ter_uavnew") * _count_rain("uavnew_sat") * sat_count

        ter_cfg = _rain_cfg("ter_uavnew")
        uav_cfg = _rain_cfg("uavnew_sat")
        sat_rtts = _listify(sat_cfg.get("rtt_ms", 0.0))
        allowed_rtts = {
            round(ter_rtt + uav_rtt + sat_rtt, 3)
            for ter_rtt in _listify(ter_cfg.get("base_rtt_ms", ter_cfg.get("rtt_ms", 0.0)))
            for uav_rtt in _listify(uav_cfg.get("base_rtt_ms", uav_cfg.get("rtt_ms", 0.0)))
            for sat_rtt in sat_rtts
        }
        ter_states = set(ter_cfg["states"].keys())
        uav_states = set(uav_cfg["states"].keys())

        for row in rows:
            loss_parts = str(row["loss_pct"]).split("/")
            assert len(loss_parts) == 3, "Ter→UAV_new→Sat path must report all hops"
            assert round(float(row["rtt_ms"]), 3) in allowed_rtts
            profile = str(row["rain_profile"])
            assert "→" in profile
            ter_state, uav_state = profile.split("→", 1)
            assert ter_state in ter_states
            assert uav_state in uav_states
    else:  # ren_short_window
        def _value_list(value) -> List[float]:
            if isinstance(value, (list, tuple)):
                return [float(v) for v in value]
            if value is None:
                return [0.0]
            return [float(value)]

        def _window_options(link: str) -> List[Tuple[float, str]]:
            link_cfg = config["links"][link]
            rtts = _value_list(link_cfg.get("rtt_ms", 0.0)) or [0.0]
            profiles = link_cfg.get("window_profiles", {})
            profile_names = [str(name) for name in profiles] or ["default"]
            return [(rtt, profile) for rtt in rtts for profile in profile_names]

        sat_cfg = config["links"]["sat_ncc"]
        sat_count = (
            _count_list(sat_cfg.get("rtt_ms", 0.0))
            * _count_list(sat_cfg.get("jitter_ms", 0.0))
            * _count_list(sat_cfg.get("loss_pct", 0.0))
        )

        ter_opts = _window_options("ter_uavnew")
        uav_opts = _window_options("uavnew_sat")
        matched_pairs = [
            (ter_opt, uav_opt)
            for ter_opt in ter_opts
            for uav_opt in uav_opts
            if math.isclose(ter_opt[0], uav_opt[0], abs_tol=1e-6) and ter_opt[1] == uav_opt[1]
        ]
        base_pair_count = len(ter_opts) * len(uav_opts)
        pair_count = len(matched_pairs) if matched_pairs else base_pair_count
        expected_combos = pair_count * max(1, sat_count)

    assert combo_count == expected_combos
