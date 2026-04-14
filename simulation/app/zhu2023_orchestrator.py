#!/usr/bin/env python3
"""Scenario runner for Zhu2023 single-link authentication experiments."""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import random
import subprocess
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml

from rain_fade import RainFadeController
from window_controller import WindowController

DEFAULT_CONTEXT_HOST_PATH = Path(__file__).resolve().parents[1] / "shared" / "offline_context_zhu.pkl"
DEFAULT_CONTEXT_CONTAINER_PATH = Path("/shared/offline_context_zhu.pkl")


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
    ensure_containers_running([container])
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
    try:
        run_command(netem_cmd)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Failed to apply netem on container '{container}' (interface {interface}). "
            f"Ensure docker compose is running.\nstdout: {exc.stdout}\nstderr: {exc.stderr}"
        ) from exc


def clear_netem(container: str, interface: str) -> None:
    if not container:
        return
    inspect = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if inspect.returncode != 0 or inspect.stdout.strip().lower() != "true":
        return
    cmd = ["docker", "exec", container, "tc", "qdisc", "del", "dev", interface, "root"]
    subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def ensure_metric_fields(record: Dict) -> None:
    record.setdefault("scenario", "")
    record.setdefault("mode", "")
    record.setdefault("rtt_ms", "")
    record.setdefault("loss_pct", "")
    record.setdefault("timeout_ms", "")
    record.setdefault("pto", "")
    record.setdefault("run", "")
    record.setdefault("status", "")
    record.setdefault("failed_stage", "")
    record.setdefault("errno", 0)
    record.setdefault("attempts", 0)
    record.setdefault("cpu_ms_ue", 0.0)
    record.setdefault("cpu_ms_leo2", 0.0)
    record.setdefault("processing_ms_leo2", 0.0)
    record.setdefault("bytes_online", float(record.get("bytes_online", 0.0)))
    record.setdefault("msgs_online", int(record.get("msgs_online", record.get("attempts", 0))))
    record.setdefault("bytes_ue", float(record.get("bytes_ue", record.get("bytes_online", 0.0))))
    record.setdefault("bytes_leo2", float(record.get("bytes_leo2", 0.0)))
    record.setdefault("msgs_ue", int(record.get("msgs_ue", record.get("msgs_online", 0))))
    record.setdefault("msgs_leo2", int(record.get("msgs_leo2", 0)))
    record.setdefault("latency_ms", float(record.get("latency_ms", 0.0)))
    record.setdefault("ts5", "")
    record.setdefault("ts6", "")
    record.setdefault("rain_profile", "")
    record.setdefault("bw_factor", "")
    record.setdefault("down_rate_mbps", "")
    record.setdefault("up_rate_mbps", "")
    record.setdefault("bad_ticks", "")
    record.setdefault("total_ticks", "")
    record.setdefault("bad_ratio", "")
    record.setdefault("blackout_events", "")
    record.setdefault("blackout_ticks", "")
    record.setdefault("window_profile", "")
    record.setdefault("window_duration_ms", "")
    record.setdefault("uplink_delay_ms", "")
    record.setdefault("down_ready_ms", "")
    record.setdefault("guard_close_ms", "")
    record.setdefault("scheduled_blackouts", "")


def ensure_containers_running(containers: Iterable[str]) -> None:
    missing: List[str] = []
    for name in containers:
        if not name:
            continue
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0 or result.stdout.strip().lower() != "true":
            missing.append(name)
    if missing:
        raise RuntimeError(
            "Required docker containers are not running: "
            + ", ".join(missing)
            + "\nPlease launch them with "
            + "'docker compose -f simulation/docker-compose-zhu2023.yml up -d'."
        )


def value_list(value: Any, *, default: float) -> List[float]:
    if value is None:
        return [default]
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        values = list(value)
        return values if values else [default]
    return [float(value)]


def invoke_ue_client(
    *,
    ue_id: str,
    timeout_ms: int,
    pto: int,
    context_container_path: Path,
    rsu_host: str,
    rsu_port: int,
) -> Dict:
    cmd = [
        "docker",
        "exec",
        "ue",
        "python",
        "/app/app/zhu2023_ue_client.py",
        "--context",
        str(context_container_path),
        "--ue-id",
        ue_id,
        "--timeout-ms",
        str(timeout_ms),
        "--pto",
        str(pto),
        "--rsu-host",
        rsu_host,
        "--rsu-port",
        str(rsu_port),
    ]
    try:
        proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        emit_container_output("ZHU-UE", stdout, stderr)
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        if lines:
            try:
                payload = json.loads(lines[-1])
                if isinstance(payload, dict):
                    payload.setdefault("status", "failed")
                    payload.setdefault("failed_stage", "client")
                    return payload
            except json.JSONDecodeError:
                pass
        return {
            "status": "failed",
            "failed_stage": "client",
            "errno": 0,
            "attempts": 0,
            "timeout_ms": timeout_ms,
            "pto": pto,
            "latency_ms": 0.0,
            "bytes_online": 0.0,
            "msgs_online": 0,
            "cpu_ms_ue": 0.0,
        }
    emit_container_output("ZHU-UE", proc.stdout, proc.stderr)
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("UE client produced no output")
    return json.loads(lines[-1])


def run_single_link_scenario(
    *,
    args: argparse.Namespace,
    config: Dict[str, Any],
    writer: csv.DictWriter,
    out_fh,
    summary: Dict[Tuple[str, int, int], Dict[str, int]],
    runs: int,
    timeouts: Iterable[int],
    pto_values: Iterable[int],
) -> None:
    link_cfg = config["ue_leo2"]
    rtt_values = value_list(link_cfg.get("rtt_ms"), default=0.0)
    jitter_values = value_list(link_cfg.get("jitter_ms", 0.0), default=0.0)
    loss_values = value_list(link_cfg.get("loss_pct", 0.0), default=0.0)
    rate_values = value_list(link_cfg.get("rate_mbps", None), default=None) if link_cfg.get("rate_mbps") is not None else [None]

    ensure_containers_running(["ue", "rsu"])

    for (rtt_ms, jitter_ms, loss_pct, rate_mbps) in itertools.product(rtt_values, jitter_values, loss_values, rate_values):
        for timeout_ms in timeouts:
            for pto in pto_values:
                summary_key = (config.get("name", ""), timeout_ms, pto)
                for run_index in range(1, runs + 1):
                    apply_netem("ue", args.ue_interface, rtt_ms, jitter_ms, loss_pct, rate_mbps=rate_mbps)
                    apply_netem("rsu", args.rsu_interface, rtt_ms, jitter_ms, loss_pct, rate_mbps=rate_mbps)

                    record = invoke_ue_client(
                        ue_id=args.ue_id,
                        timeout_ms=timeout_ms,
                        pto=pto,
                        context_container_path=args.context_container_path,
                        rsu_host=args.rsu_host,
                        rsu_port=args.rsu_port,
                    )
                    ensure_metric_fields(record)
                    record.update(
                        {
                            "scenario": config.get("name", ""),
                            "mode": config.get("mode", ""),
                            "run": run_index,
                            "timeout_ms": timeout_ms,
                            "pto": pto,
                            "rtt_ms": rtt_ms,
                            "loss_pct": loss_pct,
                            "rain_profile": "",
                            "bw_factor": "",
                            "down_rate_mbps": "",
                            "up_rate_mbps": "",
                            "bad_ticks": "",
                            "total_ticks": "",
                            "bad_ratio": "",
                            "blackout_events": "",
                            "blackout_ticks": "",
                        }
                    )

                    writer.writerow({field: record.get(field, "") for field in writer.fieldnames})
                    out_fh.flush()

                    summary[summary_key]["total"] += 1
                    if record.get("status") == "ok":
                        summary[summary_key]["success"] += 1

    clear_netem("ue", args.ue_interface)
    clear_netem("rsu", args.rsu_interface)


def run_rain_fade_scenario(
    *,
    args: argparse.Namespace,
    config: Dict[str, Any],
    writer: csv.DictWriter,
    out_fh,
    summary: Dict[Tuple[str, int, int], Dict[str, int]],
    runs: int,
    timeouts: Iterable[int],
    pto_values: Iterable[int],
) -> None:
    rf_cfg = config["ue_leo2"]
    base_rtts = value_list(rf_cfg.get("base_rtt_ms"), default=0.0)
    base_jitter = float(rf_cfg.get("jitter_ms", 0.0))
    step_ms = int(rf_cfg.get("ge_step_ms", 100))
    base_down_mbps = float(rf_cfg.get("base_down_mbps", 100.0))
    base_up_mbps = float(rf_cfg.get("base_up_mbps", 20.0))
    bad_jitter_extra = float(rf_cfg.get("bad_jitter_extra_ms", 0.0))
    queue_limit = rf_cfg.get("queue_limit")
    downlink_only = bool(rf_cfg.get("downlink_only", False))
    seed_base = rf_cfg.get("seed")
    states = rf_cfg.get("states", {})

    ensure_containers_running(["ue", "rsu"])

    for base_rtt in base_rtts:
        for profile_name, profile_cfg in states.items():
            bw_factor = float(profile_cfg.get("bw_factor", 1.0))
            down_rate = base_down_mbps * bw_factor
            up_rate = base_up_mbps * bw_factor
            loss_good = float(profile_cfg.get("loss_good", 0.0))
            loss_bad = float(profile_cfg.get("loss_bad", loss_good))
            p_gb = float(profile_cfg.get("p_gb", 0.0))
            p_bg = float(profile_cfg.get("p_bg", 0.0))
            micro_blackout_cfg = profile_cfg.get("micro_blackout")

            for timeout_ms in timeouts:
                for pto in pto_values:
                    summary_key = (config.get("name", ""), timeout_ms, pto)
                    for run_index in range(1, runs + 1):
                        seed = None
                        if seed_base is not None:
                            seed = int(seed_base) + int(base_rtt * 1000) + run_index

                        controller = RainFadeController(
                            apply_netem=apply_netem,
                            ue_container="ue",
                            ue_interface=args.ue_interface,
                            leo2_container="rsu",
                            leo2_interface=args.rsu_interface,
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

                        controller.start()
                        try:
                            record = invoke_ue_client(
                                ue_id=args.ue_id,
                                timeout_ms=timeout_ms,
                                pto=pto,
                                context_container_path=args.context_container_path,
                                rsu_host=args.rsu_host,
                                rsu_port=args.rsu_port,
                            )
                        finally:
                            controller.stop()

                        ensure_metric_fields(record)
                        snapshot = controller.snapshot()
                        record.update(
                            {
                                "scenario": config.get("name", ""),
                                "mode": config.get("mode", ""),
                                "run": run_index,
                                "timeout_ms": timeout_ms,
                                "pto": pto,
                                "rtt_ms": base_rtt,
                                "loss_pct": loss_good,
                                "rain_profile": profile_name,
                                "bw_factor": bw_factor,
                                "down_rate_mbps": down_rate,
                                "up_rate_mbps": up_rate if not downlink_only else 0.0,
                                "bad_ticks": snapshot.get("bad_ticks", 0),
                                "total_ticks": snapshot.get("total_ticks", 0),
                                "bad_ratio": snapshot.get("bad_ratio", 0.0),
                                "blackout_events": snapshot.get("blackout_events", 0),
                                "blackout_ticks": snapshot.get("blackout_ticks", 0),
                                "ts5": record.get("ts5", ""),
                                "ts6": record.get("ts6", ""),
                            }
                        )

                        writer.writerow({field: record.get(field, "") for field in writer.fieldnames})
                        out_fh.flush()

                        summary[summary_key]["total"] += 1
                        if record.get("status") == "ok":
                            summary[summary_key]["success"] += 1

                    clear_netem("ue", args.ue_interface)
                    clear_netem("rsu", args.rsu_interface)


def _sample_range(value: Any, *, default: float = 0.0) -> float:
    if isinstance(value, (list, tuple)):
        if len(value) == 2:
            return random.uniform(float(value[0]), float(value[1]))
        if value:
            return float(value[0])
    if value is None:
        return float(default)
    return float(value)


def run_short_window_scenario(
    *,
    args: argparse.Namespace,
    config: Dict[str, Any],
    writer: csv.DictWriter,
    out_fh,
    summary: Dict[Tuple[str, int, int], Dict[str, int]],
    runs: int,
    timeouts: Iterable[int],
    pto_values: Iterable[int],
) -> None:
    sw_cfg = config["ue_leo2"]
    base_rtts = value_list(sw_cfg.get("rtt_ms"), default=0.0)
    jitter_ms = float(sw_cfg.get("jitter_ms", 0.0))
    loss_base = float(sw_cfg.get("loss_pct", 0.0))
    loss_window = float(sw_cfg.get("loss_pct_window", loss_base))
    base_down_mbps = float(sw_cfg.get("base_down_mbps", 100.0))
    base_up_mbps = float(sw_cfg.get("base_up_mbps", 20.0))
    step_ms = int(sw_cfg.get("window_step_ms", 100))
    uplink_delay_cfg = sw_cfg.get("uplink_delay_ms")
    down_ready_cfg = sw_cfg.get("downlink_ready_delay_ms")
    guard_close_cfg = sw_cfg.get("guard_close_ms")
    micro_cfg = sw_cfg.get("micro_blackout")
    window_profiles = sw_cfg.get("window_profiles", {})

    ensure_containers_running(["ue", "rsu"])

    controller = WindowController(
        ue_container="ue",
        ue_interface=args.ue_interface,
        leo2_container="rsu",
        leo2_interface=args.rsu_interface,
    )

    try:
        for base_rtt in base_rtts:
            apply_netem(
                "ue",
                args.ue_interface,
                base_rtt,
                jitter_ms,
                loss_base,
                rate_mbps=base_up_mbps,
            )
            apply_netem(
                "rsu",
                args.rsu_interface,
                base_rtt,
                jitter_ms,
                loss_base,
                rate_mbps=base_down_mbps,
            )

            for profile_name, profile_cfg in window_profiles.items():
                duration_min = float(profile_cfg.get("duration_min_s", 1.0))
                duration_max = float(profile_cfg.get("duration_max_s", duration_min))

                for timeout_ms in timeouts:
                    for pto in pto_values:
                        summary_key = (config.get("name", ""), timeout_ms, pto)
                        for run_index in range(1, runs + 1):
                            summary[summary_key]["total"] += 1

                            full_window_ms = int(round(random.uniform(duration_min, duration_max) * 1000))
                            guard_ms = int(round(max(0.0, _sample_range(guard_close_cfg, default=0.0))))
                            usable_ms = max(step_ms, full_window_ms - guard_ms)

                            controller.close()
                            window_loss_active = False
                            blackout_timers: List[threading.Timer] = []
                            try:
                                apply_netem(
                                    "ue",
                                    args.ue_interface,
                                    base_rtt,
                                    jitter_ms,
                                    loss_window,
                                    rate_mbps=base_up_mbps,
                                )
                                apply_netem(
                                    "rsu",
                                    args.rsu_interface,
                                    base_rtt,
                                    jitter_ms,
                                    loss_window,
                                    rate_mbps=base_down_mbps,
                                )
                                window_loss_active = True
                            except subprocess.CalledProcessError as exc:
                                print(f"[ZHU2023] failed to apply window netem: {exc.stderr or exc}")

                            duration_s = usable_ms / 1000.0
                            controller.open_for(duration_s)

                            down_ready_ms = int(round(max(0.0, _sample_range(down_ready_cfg, default=0.0))))
                            if down_ready_ms > 0:
                                controller.drop_downlink_for(down_ready_ms)

                            scheduled_blackouts = 0
                            if micro_cfg:
                                duration_cfg = micro_cfg.get("duration_ms", 0.0)
                                probability_cfg = micro_cfg.get("probability_per_s", 0.0)
                                if isinstance(probability_cfg, (list, tuple)) and len(probability_cfg) == 2:
                                    prob_per_s = random.uniform(float(probability_cfg[0]), float(probability_cfg[1]))
                                else:
                                    prob_per_s = float(probability_cfg)
                                prob_per_tick = prob_per_s * (step_ms / 1000.0)

                                def sample_blackout_ms() -> int:
                                    value = duration_cfg
                                    if isinstance(value, (list, tuple)) and len(value) == 2:
                                        return int(round(max(step_ms, random.uniform(float(value[0]), float(value[1])))))
                                    return int(round(max(step_ms, float(value))))

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
                                        scheduled_blackouts += 1
                                        start_ms += blackout_ms
                                    else:
                                        start_ms += step_ms

                            uplink_delay_ms = int(round(max(0.0, _sample_range(uplink_delay_cfg, default=0.0))))
                            if uplink_delay_ms > 0:
                                time.sleep(uplink_delay_ms / 1000.0)

                            try:
                                record = invoke_ue_client(
                                    ue_id=args.ue_id,
                                    timeout_ms=timeout_ms,
                                    pto=pto,
                                    context_container_path=args.context_container_path,
                                    rsu_host=args.rsu_host,
                                    rsu_port=args.rsu_port,
                                )
                            finally:
                                controller.wait_for_close()
                                for timer_obj in blackout_timers:
                                    timer_obj.cancel()
                                if window_loss_active:
                                    apply_netem(
                                        "ue",
                                        args.ue_interface,
                                        base_rtt,
                                        jitter_ms,
                                        loss_base,
                                        rate_mbps=base_up_mbps,
                                    )
                                    apply_netem(
                                        "rsu",
                                        args.rsu_interface,
                                        base_rtt,
                                        jitter_ms,
                                        loss_base,
                                        rate_mbps=base_down_mbps,
                                    )

                            ensure_metric_fields(record)
                            metrics = controller.metrics()
                            record.update(
                                {
                                    "scenario": config.get("name", ""),
                                    "mode": config.get("mode", ""),
                                    "run": run_index,
                                    "timeout_ms": timeout_ms,
                                    "pto": pto,
                                    "rtt_ms": base_rtt,
                                    "loss_pct": loss_window,
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
                                    "window_duration_ms": metrics.last_window_ms,
                                    "uplink_delay_ms": uplink_delay_ms,
                                    "down_ready_ms": down_ready_ms,
                                    "guard_close_ms": guard_ms,
                                    "scheduled_blackouts": scheduled_blackouts,
                                }
                            )

                            writer.writerow({field: record.get(field, "") for field in writer.fieldnames})
                            out_fh.flush()

                            if record.get("status") == "ok":
                                summary[summary_key]["success"] += 1
    finally:
        controller.shutdown()

    clear_netem("ue", args.ue_interface)
    clear_netem("rsu", args.rsu_interface)

def load_config(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Zhu2023 single-link orchestrator")
    parser.add_argument("--config", type=Path, required=True, help="YAML scenario configuration")
    parser.add_argument("--context", type=Path, default=DEFAULT_CONTEXT_HOST_PATH, help="Offline context path (host)")
    parser.add_argument("--context-container-path", type=Path, default=DEFAULT_CONTEXT_CONTAINER_PATH)
    parser.add_argument("--output", type=Path, default=Path("results_zhu.csv"), help="CSV output path")
    parser.add_argument("--ue-id", default="veh-001", help="Vehicle identifier to exercise")
    parser.add_argument("--rsu-host", default="rsu", help="RSU hostname reachable from the UE container")
    parser.add_argument("--rsu-port", type=int, default=6000, help="RSU UDP port")
    parser.add_argument("--ue-interface", default="eth0", help="UE container interface used for the link")
    parser.add_argument("--rsu-interface", default="eth0", help="RSU container interface used for the link")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    config = load_config(args.config)

    out_path = args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    summary: Dict[Tuple[str, int, int], Dict[str, int]] = defaultdict(lambda: {"total": 0, "success": 0})

    with out_path.open("w", newline="", encoding="utf-8") as out_fh:
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
            "cpu_ms_leo2",
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
        writer = csv.DictWriter(out_fh, fieldnames=fieldnames)
        writer.writeheader()

        runs = int(config.get("runs", 1))
        timeouts = [int(value) for value in config.get("timeouts_ms", [300])]
        pto_values = [int(value) for value in config.get("pto", [0])]
        mode = str(config.get("mode", "")).upper()

        if mode in {"", "LEO_ONLY"}:
            run_single_link_scenario(
                args=args,
                config=config,
                writer=writer,
                out_fh=out_fh,
                summary=summary,
                runs=runs,
                timeouts=timeouts,
                pto_values=pto_values,
            )
        elif mode == "RAIN_FADE":
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
            run_short_window_scenario(
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
            raise ValueError(f"Unsupported scenario mode: {mode}")

    print("Summary statistics:")
    for key, value in summary.items():
        name, timeout, pto = key
        total = value["total"]
        success = value["success"]
        rate = (success / total) if total else 0.0
        print(f"  scenario={name} timeout={timeout} pto={pto} success_rate_online={rate:.3f} ({success}/{total})")


if __name__ == "__main__":
    main()
