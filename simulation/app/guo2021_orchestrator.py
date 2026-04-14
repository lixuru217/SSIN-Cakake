#!/usr/bin/env python3
"""Scenario runner for Guo2021 satellite-switch experiments."""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import random
import subprocess
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from rain_fade import RainFadeController
from window_controller import WindowController

import yaml

DEFAULT_CONTEXT_HOST_PATH = Path(__file__).resolve().parents[1] / "shared" / "offline_context_guo.pkl"
DEFAULT_CONTEXT_CONTAINER_PATH = Path("/shared/offline_context_guo.pkl")


def run_command(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def emit_container_output(label: str, stdout: str, stderr: str) -> None:
    if stdout:
        for line in stdout.splitlines():
            print(f"[{label}] {line}", flush=True)
    if stderr:
        for line in stderr.splitlines():
            print(f"[{label}][stderr] {line}", flush=True)


def apply_netem(
    container: str,
    interface: str,
    rtt_ms: float,
    jitter_ms: float,
    loss_pct: float,
    *,
    rate_mbps: float | None = None,
    limit_packets: int | None = 1000,
) -> None:
    delay_ms = rtt_ms / 2.0
    netem_cmd = [
        "docker",
        "exec",
        container,
        "tc",
        "qdisc",
        "replace",
        "dev",
        interface,
        "root",
        "netem",
        "delay",
        f"{delay_ms:.3f}ms",
    ]
    if jitter_ms and jitter_ms > 0:
        netem_cmd.append(f"{jitter_ms:.3f}ms")
    loss_value = max(loss_pct, 0.0) if loss_pct is not None else 0.0
    netem_cmd.extend(["loss", f"{loss_value:.4f}%"])
    if rate_mbps is not None:
        netem_cmd.extend(["rate", f"{max(rate_mbps, 0.001):.3f}Mbit"])
    if limit_packets:
        netem_cmd.extend(["limit", str(limit_packets)])
    run_command(netem_cmd)


def clear_netem(container: str, interface: str) -> None:
    cmd = ["docker", "exec", container, "tc", "qdisc", "del", "dev", interface, "root"]
    subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def ensure_metric_fields(record: Dict) -> None:
    record.setdefault("cpu_ms_lj", 0.0)
    record.setdefault("cpu_ms_ln", 0.0)
    record.setdefault("processing_ms_ln", 0.0)
    record.setdefault("bytes_ue", float(record.get("bytes_online", 0.0)))
    record.setdefault("bytes_lj", 0.0)
    record.setdefault("bytes_ln", 0.0)
    record.setdefault("bytes_total", float(record.get("bytes_total", record.get("bytes_online", 0.0))))
    record.setdefault("msgs_ue", int(record.get("msgs_online", record.get("attempts", 0))))
    record.setdefault("msgs_lj", 0)
    record.setdefault("msgs_ln", 0)
    record.setdefault("msgs_total", int(record.get("msgs_total", record.get("msgs_online", 0))))


def run_rain_fade_scenario(
    *,
    args: argparse.Namespace,
    config: Dict,
    writer: csv.DictWriter,
    out_fh,
    summary: Dict[Tuple, Dict[str, int]],
    runs: int,
    timeouts: Iterable[int],
    pto_values: Iterable[int],
) -> None:
    isl_cfg = config["isl_helper"]
    rain_cfg = config["ue_leo2"]
    helper_cfg = config.get("ue_leo1", rain_cfg)

    base_rtts = rain_cfg["base_rtt_ms"]
    states = rain_cfg["states"]
    base_jitter = rain_cfg.get("jitter_ms", 0.0)
    step_ms = rain_cfg.get("ge_step_ms", 50)
    base_down_mbps = rain_cfg.get("base_down_mbps", 100.0)
    base_up_mbps = rain_cfg.get("base_up_mbps", 20.0)
    downlink_only = rain_cfg.get("downlink_only", False)
    queue_limit = rain_cfg.get("queue_limit")
    default_bad_jitter_extra = rain_cfg.get("bad_jitter_extra_ms", 0.0)
    seed_base = rain_cfg.get("seed")

    helper_states = helper_cfg.get("states", {})
    helper_state_offsets = {name: idx * 10_000 for idx, name in enumerate(helper_states.keys())}
    state_offsets = {name: idx * 10_000 for idx, name in enumerate(states.keys())}

    helper_base_rtts = helper_cfg.get("base_rtt_ms", rain_cfg.get("base_rtt_ms", []))
    if not isinstance(helper_base_rtts, list):
        helper_base_rtts = [helper_base_rtts]
    helper_base_jitter = helper_cfg.get("jitter_ms", rain_cfg.get("jitter_ms", 0.0))
    helper_step_ms = helper_cfg.get("ge_step_ms", rain_cfg.get("ge_step_ms", 50))
    helper_base_down_mbps = helper_cfg.get("base_down_mbps", rain_cfg.get("base_down_mbps", 100.0))
    helper_base_up_mbps = helper_cfg.get("base_up_mbps", rain_cfg.get("base_up_mbps", 20.0))
    helper_downlink_only = helper_cfg.get("downlink_only", rain_cfg.get("downlink_only", False))
    helper_queue_limit = helper_cfg.get("queue_limit", rain_cfg.get("queue_limit"))
    helper_default_bad_jitter_extra = helper_cfg.get(
        "bad_jitter_extra_ms",
        rain_cfg.get("bad_jitter_extra_ms", 0.0),
    )
    helper_seed_base = helper_cfg.get("seed")

    helper_rtt_count = len(helper_base_rtts) or 1

    for rtt_idx, base_rtt in enumerate(base_rtts):
        helper_rtt = helper_base_rtts[rtt_idx % helper_rtt_count] if helper_base_rtts else base_rtt
        for profile_name, profile_cfg in states.items():
            helper_profile_cfg = helper_states.get(profile_name, profile_cfg)
            helper_bw_factor = float(helper_profile_cfg.get("bw_factor", profile_cfg.get("bw_factor", 1.0)))
            helper_down_rate = helper_base_down_mbps * helper_bw_factor
            helper_up_rate = helper_base_up_mbps * helper_bw_factor
            helper_loss_good = float(helper_profile_cfg.get("loss_good", profile_cfg.get("loss_good", 0.0)))
            helper_loss_bad = float(helper_profile_cfg.get("loss_bad", profile_cfg.get("loss_bad", helper_loss_good)))
            helper_p_gb = float(helper_profile_cfg.get("p_gb", profile_cfg.get("p_gb", 0.0)))
            helper_p_bg = float(helper_profile_cfg.get("p_bg", profile_cfg.get("p_bg", 0.0)))
            helper_bad_jitter_extra = float(
                helper_profile_cfg.get("jitter_bad_extra_ms", helper_default_bad_jitter_extra)
            )
            helper_micro_blackout_cfg = helper_profile_cfg.get("micro_blackout")
            if isinstance(helper_micro_blackout_cfg, str):
                helper_micro_blackout_cfg = None if helper_micro_blackout_cfg.lower() in {"off", "none"} else None

            bw_factor = float(profile_cfg["bw_factor"])
            down_rate = base_down_mbps * bw_factor
            up_rate = base_up_mbps * bw_factor
            loss_good = float(profile_cfg["loss_good"])
            loss_bad = float(profile_cfg["loss_bad"])
            p_gb = float(profile_cfg["p_gb"])
            p_bg = float(profile_cfg["p_bg"])
            bad_jitter_extra = float(profile_cfg.get("jitter_bad_extra_ms", default_bad_jitter_extra))
            micro_blackout_cfg = profile_cfg.get("micro_blackout")
            if isinstance(micro_blackout_cfg, str):
                micro_blackout_cfg = None if micro_blackout_cfg.lower() in {"off", "none"} else None

            for timeout_ms in timeouts:
                for pto in pto_values:
                    for run_index in range(1, runs + 1):
                        summary_key = (profile_name, base_rtt, timeout_ms, pto)
                        summary[summary_key]["total"] += 1

                        helper_jitter = helper_base_jitter
                        apply_netem(
                            "ue",
                            args.ue_helper_interface,
                            helper_rtt,
                            helper_jitter,
                            helper_loss_good,
                            rate_mbps=helper_up_rate,
                        )
                        apply_netem(
                            "leo1",
                            args.leo1_interface,
                            helper_rtt,
                            helper_jitter,
                            helper_loss_good,
                            rate_mbps=helper_down_rate,
                        )
                        apply_netem(
                            "leo1",
                            args.leo1_isl_interface,
                            isl_cfg["rtt_ms"],
                            isl_cfg.get("jitter_ms", 0.0),
                            isl_cfg.get("loss_pct", 0.0),
                        )
                        apply_netem(
                            "leo2",
                            args.leo2_isl_interface,
                            isl_cfg["rtt_ms"],
                            isl_cfg.get("jitter_ms", 0.0),
                            isl_cfg.get("loss_pct", 0.0),
                        )

                        seed = None
                        if seed_base is not None:
                            seed = int(
                                seed_base
                                + state_offsets[profile_name]
                                + (base_rtt * 100)
                                + (timeout_ms * 10)
                                + (pto * 5)
                                + run_index
                            )

                        helper_seed = None
                        if helper_seed_base is not None:
                            helper_seed = int(
                                helper_seed_base
                                + helper_state_offsets.get(profile_name, 0)
                                + (helper_rtt * 100)
                                + (timeout_ms * 10)
                                + (pto * 5)
                                + run_index
                            )

                        controllers: List[RainFadeController] = []
                        primary_controller = RainFadeController(
                            apply_netem=apply_netem,
                            ue_container="ue",
                            ue_interface=args.ue_interface,
                            leo2_container="leo2",
                            leo2_interface=args.leo2_interface,
                            base_rtt_ms=base_rtt,
                            base_jitter_ms=base_jitter,
                            loss_good_pct=loss_good,
                            loss_bad_pct=loss_bad,
                            p_gb=p_gb,
                            p_bg=p_bg,
                            step_ms=step_ms,
                            down_rate_mbps=down_rate,
                            up_rate_mbps=up_rate,
                            bw_factor=bw_factor,
                            bad_jitter_extra_ms=bad_jitter_extra,
                            queue_limit=queue_limit,
                            downlink_only=downlink_only,
                            seed=seed,
                            micro_blackout=micro_blackout_cfg,
                        )
                        controllers.append(primary_controller)

                        helper_controller = RainFadeController(
                            apply_netem=apply_netem,
                            ue_container="ue",
                            ue_interface=args.ue_helper_interface,
                            leo2_container="leo1",
                            leo2_interface=args.leo1_interface,
                            base_rtt_ms=helper_rtt,
                            base_jitter_ms=helper_base_jitter,
                            loss_good_pct=helper_loss_good,
                            loss_bad_pct=helper_loss_bad,
                            p_gb=helper_p_gb,
                            p_bg=helper_p_bg,
                            step_ms=helper_step_ms,
                            down_rate_mbps=helper_down_rate,
                            up_rate_mbps=helper_up_rate,
                            bw_factor=helper_bw_factor,
                            bad_jitter_extra_ms=helper_bad_jitter_extra,
                            queue_limit=helper_queue_limit,
                            downlink_only=helper_downlink_only,
                            seed=helper_seed,
                            micro_blackout=helper_micro_blackout_cfg,
                        )
                        controllers.append(helper_controller)

                        for ctrl in controllers:
                            ctrl.start()
                        try:
                            auth_result = invoke_auth_client(
                                ue_id=args.ue_id,
                                timeout_ms=timeout_ms,
                                pto=pto,
                                context_container_path=args.context_container,
                                sat_host=args.helper_host,
                                sat_port=args.helper_port,
                            )
                            if auth_result.get("status") != "ok":
                                record = {
                                    "status": auth_result.get("status", "failed"),
                                    "failed_stage": auth_result.get("failed_stage", "auth"),
                                    "errno": auth_result.get("errno", 0),
                                    "attempts": auth_result.get("attempts", 0),
                                    "latency_ms": auth_result.get("latency_ms", 0.0),
                                    "bytes_online": auth_result.get("bytes_online", 0),
                                    "msgs_online": auth_result.get("msgs_online", 0),
                                    "cpu_ms_ue": auth_result.get("cpu_ms_ue", 0.0),
                                    "cpu_ms_lj": 0.0,
                                    "cpu_ms_ln": 0.0,
                                    "processing_ms_ln": auth_result.get("processing_ms_ln", 0.0),
                                    "bytes_ue": auth_result.get("bytes_ue", auth_result.get("bytes_online", 0.0)),
                                    "bytes_lj": 0.0,
                                    "bytes_ln": 0.0,
                                    "bytes_total": float(auth_result.get("bytes_online", 0)),
                                    "msgs_ue": auth_result.get("msgs_online", 0),
                                    "msgs_lj": 0,
                                    "msgs_ln": 0,
                                    "msgs_total": auth_result.get("msgs_online", 0),
                                    "ts5": "",
                                    "ts6": "",
                                }
                            else:
                                record = invoke_guo_client(
                                    ue_id=args.ue_id,
                                    timeout_ms=timeout_ms,
                                    pto=pto,
                                    context_container_path=args.context_container,
                                    old_sat_host=args.helper_host,
                                    old_sat_port=args.helper_port,
                                )
                                if record.get("status") == "ok":
                                    record["attempts"] = auth_result.get("attempts", record.get("attempts", 0))
                            ensure_metric_fields(record)
                        finally:
                            for ctrl in controllers:
                                ctrl.stop()

                        metrics = primary_controller.snapshot()
                        ensure_metric_fields(record)
                        record.update(
                            {
                                "scenario": config.get("name", "scenario"),
                                "mode": config.get("mode", ""),
                                "rtt_ms": base_rtt,
                                "loss_pct": "",
                                "timeout_ms": timeout_ms,
                                "pto": pto,
                                "run": run_index,
                                "rain_profile": profile_name,
                                "bw_factor": bw_factor,
                                "down_rate_mbps": metrics["down_rate_mbps"],
                                "up_rate_mbps": metrics["up_rate_mbps"],
                                "bad_ticks": metrics["bad_ticks"],
                                "total_ticks": metrics["total_ticks"],
                                "bad_ratio": metrics["bad_ratio"],
                                "blackout_events": metrics["blackout_events"],
                                "blackout_ticks": metrics["blackout_ticks"],
                                "window_profile": "",
                                "window_duration_ms": "",
                                "uplink_delay_ms": "",
                                "down_ready_ms": "",
                                "guard_close_ms": "",
                                "scheduled_blackouts": "",
                            }
                        )

                        writer.writerow({field: record.get(field, "") for field in writer.fieldnames})
                        out_fh.flush()

                        if record.get("status") == "ok":
                            summary[summary_key]["success"] += 1

            clear_netem("ue", args.ue_interface)
            clear_netem("leo2", args.leo2_interface)

    clear_netem("ue", args.ue_helper_interface)
    clear_netem("leo1", args.leo1_interface)
    clear_netem("leo1", args.leo1_isl_interface)
    clear_netem("leo2", args.leo2_isl_interface)


def run_window_scenario(
    *,
    args: argparse.Namespace,
    config: Dict,
    writer: csv.DictWriter,
    out_fh,
    summary: Dict[Tuple, Dict[str, int]],
    runs: int,
    timeouts: Iterable[int],
    pto_values: Iterable[int],
) -> None:
    isl_cfg = config["isl_helper"]
    window_cfg = config["ue_leo2"]

    base_rtts = window_cfg["rtt_ms"]
    jitter_ms = window_cfg.get("jitter_ms", 0.0)
    loss_pct_base = float(window_cfg.get("loss_pct", 0.0))
    loss_pct_window = float(window_cfg.get("loss_pct_window", loss_pct_base))
    base_down_mbps = window_cfg.get("base_down_mbps", 100.0)
    base_up_mbps = window_cfg.get("base_up_mbps", 20.0)
    window_profiles = window_cfg["window_profiles"]
    step_ms = int(window_cfg.get("window_step_ms", 100))
    uplink_delay_range = window_cfg.get("uplink_delay_ms", (0, 0))
    downlink_ready_range = window_cfg.get("downlink_ready_delay_ms", (0, 0))
    guard_close_range = window_cfg.get("guard_close_ms")
    micro_cfg = window_cfg.get("micro_blackout")

    for base_rtt in base_rtts:
        helper_loss = loss_pct_base
        apply_netem(
            "ue",
            args.ue_helper_interface,
            base_rtt,
            jitter_ms,
            helper_loss,
            rate_mbps=base_up_mbps,
        )
        apply_netem(
            "leo1",
            args.leo1_interface,
            base_rtt,
            jitter_ms,
            helper_loss,
            rate_mbps=base_down_mbps,
        )
        apply_netem(
            "leo1",
            args.leo1_isl_interface,
            isl_cfg["rtt_ms"],
            isl_cfg.get("jitter_ms", 0.0),
            isl_cfg.get("loss_pct", 0.0),
        )
        apply_netem(
            "leo2",
            args.leo2_isl_interface,
            isl_cfg["rtt_ms"],
            isl_cfg.get("jitter_ms", 0.0),
            isl_cfg.get("loss_pct", 0.0),
        )
        apply_netem(
            "ue",
            args.ue_interface,
            base_rtt,
            jitter_ms,
            loss_pct_base,
            rate_mbps=base_up_mbps,
        )
        apply_netem(
            "leo2",
            args.leo2_interface,
            base_rtt,
            jitter_ms,
            loss_pct_base,
            rate_mbps=base_down_mbps,
        )

        controller = WindowController(
            container_a="ue",
            interface_a=args.ue_interface,
            container_b="leo2",
            interface_b=args.leo2_interface,
        )

        try:
            for profile_name, profile_cfg in window_profiles.items():
                duration_min = float(profile_cfg["duration_min_s"])
                duration_max = float(profile_cfg["duration_max_s"])

                for timeout_ms in timeouts:
                    for pto in pto_values:
                        for run_index in range(1, runs + 1):
                            summary_key = (profile_name, base_rtt, timeout_ms, pto)
                            summary[summary_key]["total"] += 1

                            window_loss_active = False
                            blackout_timers: list[threading.Timer] = []

                            controller.ensure_open()
                            full_window_ms = int(round(random.uniform(duration_min, duration_max) * 1000))
                            guard_ms = 0
                            if guard_close_range:
                                guard_low, guard_high = guard_close_range
                                guard_ms = int(round(random.uniform(guard_low, guard_high)))
                            usable_ms = max(step_ms, full_window_ms - guard_ms)
                            duration_s = usable_ms / 1000.0
                            controller.close()
                            try:
                                apply_netem(
                                    "ue",
                                    args.ue_interface,
                                    base_rtt,
                                    jitter_ms,
                                    loss_pct_window,
                                    rate_mbps=base_up_mbps,
                                )
                                apply_netem(
                                    "leo2",
                                    args.leo2_interface,
                                    base_rtt,
                                    jitter_ms,
                                    loss_pct_window,
                                    rate_mbps=base_down_mbps,
                                )
                                window_loss_active = True
                            except subprocess.CalledProcessError as exc:
                                print(
                                    f"[GUO-ORCH] failed to apply window loss on {args.leo2_interface}: {exc.stderr.strip() if exc.stderr else exc}"
                                )
                                raise

                            controller.open_for(duration_s)
                            down_ready_ms = 0
                            if isinstance(downlink_ready_range, (list, tuple)) and len(downlink_ready_range) == 2:
                                down_ready_ms = int(round(random.uniform(downlink_ready_range[0], downlink_ready_range[1])))
                            elif downlink_ready_range:
                                down_ready_ms = int(round(float(downlink_ready_range)))
                            down_ready_ms = max(0, down_ready_ms)
                            if down_ready_ms > 0:
                                controller.drop_downlink_for(down_ready_ms)

                            blackout_count = 0
                            if micro_cfg:
                                duration_cfg = micro_cfg.get("duration_ms", (0, 0))
                                prob_cfg = micro_cfg.get("probability_per_s", 0.0)
                                if isinstance(prob_cfg, (list, tuple)) and len(prob_cfg) == 2:
                                    prob_per_s = random.uniform(prob_cfg[0], prob_cfg[1])
                                else:
                                    prob_per_s = float(prob_cfg)
                                prob_per_tick = prob_per_s * (step_ms / 1000.0)

                                if isinstance(duration_cfg, (list, tuple)) and len(duration_cfg) == 2:
                                    def sample_blackout_ms() -> int:
                                        return int(round(max(step_ms, random.uniform(duration_cfg[0], duration_cfg[1]))))
                                else:
                                    def sample_blackout_ms() -> int:
                                        return int(round(max(step_ms, float(duration_cfg))))

                                start_ms = max(down_ready_ms, step_ms)
                                end_ms = max(start_ms, usable_ms - step_ms)
                                while start_ms < end_ms:
                                    if random.random() < prob_per_tick:
                                        blackout_ms = sample_blackout_ms()
                                        timer_obj = threading.Timer(
                                            start_ms / 1000.0,
                                            controller.inject_blackout,
                                            args=(blackout_ms,),
                                        )
                                        timer_obj.start()
                                        blackout_timers.append(timer_obj)
                                        blackout_count += 1
                                        start_ms += blackout_ms
                                    else:
                                        start_ms += step_ms

                            if isinstance(uplink_delay_range, (list, tuple)) and len(uplink_delay_range) == 2:
                                uplink_delay_ms = int(round(random.uniform(uplink_delay_range[0], uplink_delay_range[1])))
                            elif uplink_delay_range:
                                uplink_delay_ms = int(round(float(uplink_delay_range)))
                            else:
                                uplink_delay_ms = 0
                            uplink_delay_ms = max(0, uplink_delay_ms)

                            try:
                                if uplink_delay_ms > 0:
                                    time.sleep(uplink_delay_ms / 1000.0)
                                auth_result = invoke_auth_client(
                                    ue_id=args.ue_id,
                                    timeout_ms=timeout_ms,
                                    pto=pto,
                                    context_container_path=args.context_container,
                                    sat_host=args.helper_host,
                                    sat_port=args.helper_port,
                                )
                                if auth_result.get("status") != "ok":
                                    record = {
                                        "status": auth_result.get("status", "failed"),
                                        "failed_stage": auth_result.get("failed_stage", "auth"),
                                        "errno": auth_result.get("errno", 0),
                                        "attempts": auth_result.get("attempts", 0),
                                        "latency_ms": auth_result.get("latency_ms", 0.0),
                                        "bytes_online": auth_result.get("bytes_online", 0),
                                        "msgs_online": auth_result.get("msgs_online", 0),
                                        "cpu_ms_ue": auth_result.get("cpu_ms_ue", 0.0),
                                        "cpu_ms_lj": 0.0,
                                        "cpu_ms_ln": 0.0,
                                        "processing_ms_ln": auth_result.get("processing_ms_ln", 0.0),
                                        "bytes_ue": auth_result.get("bytes_ue", auth_result.get("bytes_online", 0.0)),
                                        "bytes_lj": 0.0,
                                        "bytes_ln": 0.0,
                                        "bytes_total": float(auth_result.get("bytes_online", 0)),
                                        "msgs_ue": auth_result.get("msgs_online", 0),
                                        "msgs_lj": 0,
                                        "msgs_ln": 0,
                                        "msgs_total": auth_result.get("msgs_online", 0),
                                        "ts5": "",
                                        "ts6": "",
                                    }
                                else:
                                    record = invoke_guo_client(
                                        ue_id=args.ue_id,
                                        timeout_ms=timeout_ms,
                                        pto=pto,
                                        context_container_path=args.context_container,
                                        old_sat_host=args.helper_host,
                                        old_sat_port=args.helper_port,
                                    )
                                    if record.get("status") == "ok":
                                        record["attempts"] = auth_result.get("attempts", record.get("attempts", 0))
                                    ensure_metric_fields(record)
                            finally:
                                controller.wait_for_close()
                                for timer_obj in blackout_timers:
                                    timer_obj.cancel()
                                if window_loss_active:
                                    try:
                                        apply_netem(
                                            "ue",
                                            args.ue_interface,
                                            base_rtt,
                                            jitter_ms,
                                            loss_pct_base,
                                            rate_mbps=base_up_mbps,
                                        )
                                        apply_netem(
                                            "leo2",
                                            args.leo2_interface,
                                            base_rtt,
                                            jitter_ms,
                                            loss_pct_base,
                                            rate_mbps=base_down_mbps,
                                        )
                                        window_loss_active = False
                                    except subprocess.CalledProcessError as exc:
                                        print(
                                            f"[GUO-ORCH] failed to restore baseline netem: {exc.stderr.strip() if exc.stderr else exc}"
                                        )
                            metrics = controller.metrics()
                            window_duration_ms = metrics.last_window_ms

                            record.update(
                                {
                                    "scenario": config.get("name", "scenario"),
                                    "mode": config.get("mode", ""),
                                    "rtt_ms": base_rtt,
                                    "loss_pct": record.get("loss_pct", loss_pct_window),
                                    "timeout_ms": timeout_ms,
                                    "pto": pto,
                                    "run": run_index,
                                    "rain_profile": "",
                                    "bw_factor": "",
                                    "down_rate_mbps": "",
                                    "up_rate_mbps": "",
                                    "bad_ticks": "",
                                    "total_ticks": "",
                                    "bad_ratio": "",
                                    "blackout_events": "",
                                    "blackout_ticks": "",
                                    "window_profile": profile_name,
                                    "window_duration_ms": window_duration_ms,
                                    "uplink_delay_ms": uplink_delay_ms,
                                    "down_ready_ms": down_ready_ms,
                                    "guard_close_ms": guard_ms,
                                    "scheduled_blackouts": blackout_count,
                                }
                            )

                            writer.writerow({field: record.get(field, "") for field in writer.fieldnames})
                            out_fh.flush()

                            if record.get("status") == "ok":
                                summary[summary_key]["success"] += 1

        finally:
            controller.shutdown()

    clear_netem("ue", args.ue_interface)
    clear_netem("leo2", args.leo2_interface)
    clear_netem("ue", args.ue_helper_interface)
    clear_netem("leo1", args.leo1_interface)
    clear_netem("leo1", args.leo1_isl_interface)
    clear_netem("leo2", args.leo2_isl_interface)


def invoke_guo_client(
    ue_id: str,
    timeout_ms: int,
    pto: int,
    context_container_path: Path,
    old_sat_host: str,
    old_sat_port: int,
) -> Dict:
    cmd = [
        "docker",
        "exec",
        "ue",
        "python",
        "/app/app/guo2021_switch_client.py",
        "--context",
        str(context_container_path),
        "--ue-id",
        ue_id,
        "--timeout-ms",
        str(timeout_ms),
        "--pto",
        str(pto),
        "--old-sat-host",
        old_sat_host,
        "--old-sat-port",
        str(old_sat_port),
    ]
    try:
        proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        emit_container_output("GUO-UE", stdout, stderr)
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        if lines:
            try:
                payload = json.loads(lines[-1])
                if isinstance(payload, dict):
                    payload.setdefault("status", "failed")
                    payload.setdefault("failed_stage", "switch_client")
                    return payload
            except json.JSONDecodeError:
                pass
        return {
            "status": "failed",
            "failed_stage": "switch_client",
            "errno": 0,
            "attempts": 0,
            "latency_ms": 0.0,
            "bytes_online": 0,
            "msgs_online": 0,
            "cpu_ms_ue": 0.0,
            "processing_ms_ln": 0.0,
            "bytes_ue": 0.0,
            "bytes_lj": 0.0,
            "bytes_ln": 0.0,
            "msgs_ue": 0,
            "msgs_lj": 0,
            "msgs_ln": 0,
            "msgs_total": 0,
            "bytes_total": 0.0,
            "ts5": "",
            "ts6": "",
        }
    emit_container_output("GUO-UE", proc.stdout, proc.stderr)
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("switch client produced no output")
    return json.loads(lines[-1])


def invoke_auth_client(
    ue_id: str,
    timeout_ms: int,
    pto: int,
    context_container_path: Path,
    sat_host: str,
    sat_port: int,
) -> Dict:
    cmd = [
        "docker",
        "exec",
        "ue",
        "python",
        "/app/app/guo2021_ue_client.py",
        "--context",
        str(context_container_path),
        "--ue-id",
        ue_id,
        "--timeout-ms",
        str(timeout_ms),
        "--pto",
        str(pto),
        "--sat-host",
        sat_host,
        "--sat-port",
        str(sat_port),
    ]
    try:
        proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        emit_container_output("GUO-AUTH", stdout, stderr)
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        if lines:
            try:
                payload = json.loads(lines[-1])
                if isinstance(payload, dict):
                    payload.setdefault("status", "failed")
                    payload.setdefault("failed_stage", "auth_client")
                    return payload
            except json.JSONDecodeError:
                pass
        return {
            "status": "failed",
            "failed_stage": "auth_client",
            "errno": 0,
            "attempts": 0,
            "latency_ms": 0.0,
            "bytes_online": 0,
            "msgs_online": 0,
            "cpu_ms_ue": 0.0,
            "processing_ms_ln": 0.0,
            "bytes_ue": 0.0,
            "bytes_lj": 0.0,
            "bytes_ln": 0.0,
            "bytes_total": 0.0,
            "msgs_ue": 0,
            "msgs_lj": 0,
            "msgs_ln": 0,
            "msgs_total": 0,
            "ts1": "",
            "ts4": "",
        }
    emit_container_output("GUO-AUTH", proc.stdout, proc.stderr)
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("auth client produced no output")
    return json.loads(lines[-1])


def load_config(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def ensure_offline_context(
    context_path: Path,
    ue_ids: Iterable[str],
    old_sat_id: str,
    new_sat_id: str,
    ground_id: str,
) -> None:
    if context_path.exists():
        return
    cmd = [
        sys.executable,
        str(Path(__file__).with_name("guo2021_generate_context.py")),
        "--output",
        str(context_path),
        "--ue-ids",
        *ue_ids,
        "--old-sat-id",
        old_sat_id,
        "--new-sat-id",
        new_sat_id,
        "--ground-id",
        ground_id,
    ]
    run_command(cmd)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Guo2021 simulation scenario")
    parser.add_argument("--config", type=Path, required=True, help="Scenario YAML configuration")
    parser.add_argument("--output", type=Path, required=True, help="Destination results CSV file")
    parser.add_argument(
        "--context-host",
        type=Path,
        default=DEFAULT_CONTEXT_HOST_PATH,
        help="Offline context path on host",
    )
    parser.add_argument(
        "--context-container",
        type=Path,
        default=DEFAULT_CONTEXT_CONTAINER_PATH,
        help="Offline context path inside containers",
    )
    parser.add_argument("--ue-interface", default="eth0")
    parser.add_argument("--ue-helper-interface", default="eth1")
    parser.add_argument("--leo2-interface", default="eth0")
    parser.add_argument("--leo2-isl-interface", default="eth1")
    parser.add_argument("--leo1-interface", default="eth0")
    parser.add_argument("--leo1-isl-interface", default="eth1")
    parser.add_argument("--ue-id", default="ue-001")
    parser.add_argument("--helper-host", default="leo1")
    parser.add_argument("--helper-port", type=int, default=6000)
    parser.add_argument("--old-sat-id", default="L-01")
    parser.add_argument("--new-sat-id", default="L-02")
    parser.add_argument("--ground-id", default="GS-01")
    parser.add_argument(
        "--runs",
        type=int,
        default=None,
        help="Number of runs per parameter cell (overrides config; default 20 if unspecified)",
    )
    args = parser.parse_args()

    args.config = args.config.resolve()
    args.output = args.output.resolve()
    args.context_host = args.context_host.resolve()

    config = load_config(args.config)
    mode = str(config.get("mode", "")).upper()

    timeouts = config["timeouts_ms"]
    pto_values = config["pto"]
    config_runs = config.get("runs")
    if args.runs is not None:
        runs = args.runs
    elif config_runs is not None:
        runs = int(config_runs)
    else:
        runs = 20

    ensure_offline_context(args.context_host, [args.ue_id], args.old_sat_id, args.new_sat_id, args.ground_id)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    summary: Dict[Tuple, Dict[str, int]] = defaultdict(lambda: {"success": 0, "total": 0})

    fieldnames = [
        "scenario",
        "mode",
        "rtt_ms",
        "loss_pct",
        "timeout_ms",
        "pto",
        "run",
        "status",
        "failed_stage",
        "errno",
        "attempts",
        "latency_ms",
        "bytes_online",
        "msgs_online",
        "cpu_ms_ue",
        "cpu_ms_lj",
        "cpu_ms_ln",
        "processing_ms_ln",
        "bytes_ue",
        "bytes_lj",
        "bytes_ln",
        "bytes_total",
        "msgs_ue",
        "msgs_lj",
        "msgs_ln",
        "msgs_total",
        "ts5",
        "ts6",
        "rain_profile",
        "bw_factor",
        "down_rate_mbps",
        "up_rate_mbps",
        "bad_ticks",
        "total_ticks",
        "bad_ratio",
        "blackout_events",
        "blackout_ticks",
        "window_profile",
        "window_duration_ms",
        "uplink_delay_ms",
        "down_ready_ms",
        "guard_close_ms",
        "scheduled_blackouts",
    ]

    with args.output.open("w", encoding="utf-8", newline="") as out_fh:
        writer = csv.DictWriter(out_fh, fieldnames=fieldnames)
        writer.writeheader()

        if mode == "RAIN_FADE":
            run_rain_fade_scenario(
                args=args,
                config=config,
                writer=writer,
                out_fh=out_fh,
                summary=summary,
                runs=runs,
                timeouts=timeouts,
                pto_values=pto_values,
            )
        elif mode == "SHORT_WINDOW":
            run_window_scenario(
                args=args,
                config=config,
                writer=writer,
                out_fh=out_fh,
                summary=summary,
                runs=runs,
                timeouts=timeouts,
                pto_values=pto_values,
            )
        else:
            ue_leo2_cfg = config["ue_leo2"]
            isl_cfg = config["isl_helper"]
            rtts = ue_leo2_cfg["rtt_ms"]
            loss_values = ue_leo2_cfg["loss_pct"]
            jitter_ms = ue_leo2_cfg.get("jitter_ms", 0)

            for rtt_ms, loss_pct, timeout_ms, pto in itertools.product(rtts, loss_values, timeouts, pto_values):
                apply_netem("ue", args.ue_interface, rtt_ms, jitter_ms, loss_pct)
                apply_netem("leo2", args.leo2_interface, rtt_ms, jitter_ms, loss_pct)
                apply_netem("ue", args.ue_helper_interface, rtt_ms, jitter_ms, loss_pct)
                apply_netem("leo1", args.leo1_interface, rtt_ms, jitter_ms, loss_pct)
                apply_netem("leo1", args.leo1_isl_interface, isl_cfg["rtt_ms"], isl_cfg.get("jitter_ms", 0), isl_cfg.get("loss_pct", 0.0))
                apply_netem("leo2", args.leo2_isl_interface, isl_cfg["rtt_ms"], isl_cfg.get("jitter_ms", 0), isl_cfg.get("loss_pct", 0.0))

                for run_index in range(1, runs + 1):
                    summary_key = (rtt_ms, loss_pct, timeout_ms, pto)
                    summary[summary_key]["total"] += 1

                    auth_result = invoke_auth_client(
                        ue_id=args.ue_id,
                        timeout_ms=timeout_ms,
                        pto=pto,
                        context_container_path=args.context_container,
                        sat_host=args.helper_host,
                        sat_port=args.helper_port,
                    )
                    if auth_result.get("status") != "ok":
                        record = {
                            "status": auth_result.get("status", "failed"),
                            "failed_stage": auth_result.get("failed_stage", "auth"),
                            "errno": auth_result.get("errno", 0),
                            "attempts": auth_result.get("attempts", 0),
                            "latency_ms": auth_result.get("latency_ms", 0.0),
                            "bytes_online": auth_result.get("bytes_online", 0),
                            "msgs_online": auth_result.get("msgs_online", 0),
                            "cpu_ms_ue": auth_result.get("cpu_ms_ue", 0.0),
                            "cpu_ms_lj": 0.0,
                            "cpu_ms_ln": 0.0,
                            "processing_ms_ln": auth_result.get("processing_ms_ln", 0.0),
                            "bytes_ue": auth_result.get("bytes_ue", auth_result.get("bytes_online", 0.0)),
                            "bytes_lj": 0.0,
                            "bytes_ln": 0.0,
                            "bytes_total": float(auth_result.get("bytes_online", 0)),
                            "msgs_ue": auth_result.get("msgs_online", 0),
                            "msgs_lj": 0,
                            "msgs_ln": 0,
                            "msgs_total": auth_result.get("msgs_online", 0),
                            "ts5": "",
                            "ts6": "",
                        }
                    else:
                        record = invoke_guo_client(
                            ue_id=args.ue_id,
                            timeout_ms=timeout_ms,
                            pto=pto,
                            context_container_path=args.context_container,
                            old_sat_host=args.helper_host,
                            old_sat_port=args.helper_port,
                        )
                        if record.get("status") == "ok":
                            record["attempts"] = auth_result.get("attempts", record.get("attempts", 0))
                    record.update(
                        {
                            "scenario": config.get("name", "scenario"),
                            "mode": config.get("mode", ""),
                            "rtt_ms": rtt_ms,
                            "loss_pct": loss_pct,
                            "timeout_ms": timeout_ms,
                            "pto": pto,
                            "run": run_index,
                            "failed_stage": record.get("failed_stage", ""),
                            "errno": record.get("errno", 0),
                            "ts5": record.get("ts5", ""),
                            "ts6": record.get("ts6", ""),
                            "rain_profile": "",
                            "bw_factor": "",
                            "down_rate_mbps": "",
                            "up_rate_mbps": "",
                            "bad_ticks": "",
                            "total_ticks": "",
                            "bad_ratio": "",
                            "blackout_events": "",
                            "blackout_ticks": "",
                            "window_profile": "",
                            "window_duration_ms": "",
                            "uplink_delay_ms": "",
                            "down_ready_ms": "",
                            "guard_close_ms": "",
                            "scheduled_blackouts": "",
                        }
                    )
                    writer.writerow({field: record.get(field, "") for field in fieldnames})
                    out_fh.flush()

                    if record.get("status") == "ok":
                        summary[summary_key]["success"] += 1

                clear_netem("ue", args.ue_interface)
                clear_netem("leo2", args.leo2_interface)
                clear_netem("ue", args.ue_helper_interface)
                clear_netem("leo1", args.leo1_interface)
                clear_netem("leo1", args.leo1_isl_interface)
                clear_netem("leo2", args.leo2_isl_interface)

    print("=== Summary ===")
    if mode == "RAIN_FADE":
        for (profile_name, rtt_ms, timeout_ms, pto), stats in summary.items():
            rate = stats["success"] / stats["total"] if stats["total"] else 0.0
            print(
                f"profile={profile_name} rtt={rtt_ms}ms timeout={timeout_ms}ms pto={pto} "
                f"success_rate={rate:.3f} ({stats['success']}/{stats['total']})"
            )
    elif mode == "SHORT_WINDOW":
        for (profile_name, rtt_ms, timeout_ms, pto), stats in summary.items():
            rate = stats["success"] / stats["total"] if stats["total"] else 0.0
            print(
                f"window={profile_name} rtt={rtt_ms}ms timeout={timeout_ms}ms pto={pto} "
                f"success_rate={rate:.3f} ({stats['success']}/{stats['total']})"
            )
    else:
        for (rtt_ms, loss_pct, timeout_ms, pto), stats in summary.items():
            rate = stats["success"] / stats["total"] if stats["total"] else 0.0
            print(
                f"rtt={rtt_ms}ms loss={loss_pct}% timeout={timeout_ms}ms pto={pto} "
                f"success_rate={rate:.3f} ({stats['success']}/{stats['total']})"
            )


if __name__ == "__main__":
    main()
