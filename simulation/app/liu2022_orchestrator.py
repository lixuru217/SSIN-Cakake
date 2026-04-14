#!/usr/bin/env python3
"""Scenario runner for Liu2022 authentication experiments (static window profiles)."""

from __future__ import annotations

import argparse
import csv
import json
import random
import subprocess
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml

from rain_fade import RainFadeController
from window_controller import WindowController

DEFAULT_CONTEXT_HOST_PATH = Path(__file__).resolve().parents[1] / "shared" / "offline_context_liu.pkl"
DEFAULT_CACHE_HOST_PATH = Path(__file__).resolve().parents[1] / "shared" / "runtime"

SHARED_HOST_ROOT = Path(__file__).resolve().parents[1] / "shared"
SHARED_CONTAINER_ROOT = Path("/shared")

_NETEM_REQUESTED = True
_NETEM_AVAILABLE = True
_NETEM_WARNED = False
_PERMISSION_DENIED_SNIPPET = "permission denied while trying to connect to the docker daemon socket"


def to_container_path(path: Path) -> Path:
    """Translate a host path under ./shared to the container mount."""
    path = Path(path)
    path_str = str(path)
    if path.is_absolute() and path_str.startswith(str(SHARED_CONTAINER_ROOT)):
        return path
    try:
        resolved = path.resolve(strict=False)
    except Exception:  # Path.resolve may fail on some virtual paths
        resolved = path
    try:
        relative = resolved.relative_to(SHARED_HOST_ROOT.resolve(strict=False))
    except ValueError:
        return path
    return SHARED_CONTAINER_ROOT / relative


def run_command(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


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
    global _NETEM_AVAILABLE, _NETEM_WARNED
    if not _NETEM_REQUESTED or not _NETEM_AVAILABLE:
        return
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
        stderr_lower = (exc.stderr or "").lower()
        if _PERMISSION_DENIED_SNIPPET in stderr_lower:
            if not _NETEM_WARNED:
                print(
                    "[LIU2022] netem disabled: Docker socket access denied; continuing without link shaping "
                    "(pass --disable-netem to suppress this warning).",
                    file=sys.stderr,
                )
                _NETEM_WARNED = True
            _NETEM_AVAILABLE = False
            return
        raise


def clear_netem(container: str, interface: str) -> None:
    if not _NETEM_REQUESTED or not _NETEM_AVAILABLE:
        return
    cmd = ["docker", "exec", container, "tc", "qdisc", "del", "dev", interface, "root"]
    subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def iter_values(value: Iterable | float | int) -> Iterable[float]:
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        return list(value)
    return [float(value)]


def first_value(value: Iterable | float | int, default: float = 0.0) -> float:
    values = iter_values(value)
    return values[0] if values else float(default)


def run_access_client(
    *,
    ue_id: str,
    timeout_ms: int,
    pto: int,
    context_path: Path,
    cache_dir: Path,
    ap_host: str,
    ap_port: int,
) -> Dict:
    context_container_path = to_container_path(context_path)
    cache_container_dir = to_container_path(cache_dir)
    cmd = [
        "docker",
        "exec",
        "ue",
        "python",
        "/app/app/liu2022_ue_client.py",
        "--context",
        str(context_container_path),
        "--ue-id",
        ue_id,
        "--ap-host",
        ap_host,
        "--ap-port",
        str(ap_port),
        "--timeout-ms",
        str(timeout_ms),
        "--pto",
        str(pto),
        "--cache-dir",
        str(cache_container_dir),
    ]
    result = run_command(cmd)
    return json.loads(result.stdout.strip().splitlines()[-1])


def run_handover_client(
    *,
    ue_id: str,
    timeout_ms: int,
    pto: int,
    context_path: Path,
    cache_dir: Path,
    ap_host: str,
    ap_port: int,
    target_ap_id: str,
) -> Dict:
    context_container_path = to_container_path(context_path)
    cache_container_dir = to_container_path(cache_dir)
    cmd = [
        "docker",
        "exec",
        "ue",
        "python",
        "/app/app/liu2022_handover_client.py",
        "--context",
        str(context_container_path),
        "--ue-id",
        ue_id,
        "--ap-host",
        ap_host,
        "--ap-port",
        str(ap_port),
        "--timeout-ms",
        str(timeout_ms),
        "--pto",
        str(pto),
        "--target-ap-id",
        target_ap_id,
        "--cache-dir",
        str(cache_container_dir),
    ]
    try:
        result = run_command(cmd)
    except subprocess.CalledProcessError as exc:
        return {
            "status": "error",
            "failed_stage": "handover_client",
            "errno": exc.returncode,
            "attempts": 0,
            "timeout_ms": timeout_ms,
            "pto": pto,
            "latency_ms": 0.0,
            "bytes_online": 0,
            "msgs_online": 0,
            "cpu_ms_ue": 0.0,
            "cpu_ms_ap": 0.0,
            "processing_ms_ap": 0.0,
            "ts1": "",
            "ts2": "",
        }
    output = result.stdout.strip()
    if not output:
        return {
            "status": "error",
            "failed_stage": "handover_client_empty_output",
            "errno": 0,
            "attempts": 0,
            "timeout_ms": timeout_ms,
            "pto": pto,
            "latency_ms": 0.0,
            "bytes_online": 0,
            "msgs_online": 0,
            "cpu_ms_ue": 0.0,
            "cpu_ms_ap": 0.0,
            "processing_ms_ap": 0.0,
            "ts1": "",
            "ts2": "",
        }
    return json.loads(output.splitlines()[-1])


def build_result_record(
    *,
    fieldnames: List[str],
    scenario: str,
    mode: str,
    rtt_ms: float,
    loss_pct: float,
    timeout_ms: int,
    pto: int,
    run_index: int,
    access_result: Dict[str, Any],
    handover_result: Dict[str, Any] | None,
    extra: Dict[str, Any] | None = None,
) -> tuple[Dict[str, Any], bool]:
    record: Dict[str, Any] = {field: "" for field in fieldnames}
    record.update(
        {
            "scenario": scenario,
            "mode": mode,
            "rtt_ms": rtt_ms,
            "loss_pct": loss_pct,
            "timeout_ms": timeout_ms,
            "pto": pto,
            "run": run_index,
        }
    )
    if extra:
        for key, value in extra.items():
            if key in record:
                record[key] = value

    access_result = access_result or {}
    handover_result = handover_result or {}

    access_status = access_result.get("status", "failed")
    handover_status = handover_result.get("status")

    if access_status != "ok":
        status = "failed"
        details = access_result
        default_stage = "access"
    else:
        if handover_status == "ok":
            status = "ok"
            details = handover_result
            default_stage = ""
        else:
            status = "failed"
            details = handover_result
            default_stage = "handover"

    failed_stage = ""
    if status != "ok":
        failed_stage = details.get("failed_stage") or ""
        if not failed_stage:
            if handover_status == "skipped":
                failed_stage = "handover_skipped"
            elif handover_status and handover_status not in {"ok", "failed"}:
                failed_stage = handover_status
            else:
                failed_stage = default_stage or "unknown"

    record["status"] = "ok" if status == "ok" else "failed"
    record["failed_stage"] = failed_stage
    record["errno"] = details.get("errno", 0)
    record["attempts"] = details.get("attempts", details.get("msgs_online", 0))
    record["latency_ms"] = details.get("latency_ms", 0.0)
    record["bytes_online"] = details.get("bytes_online", 0)
    record["msgs_online"] = details.get("msgs_online", 0)
    record["cpu_ms_ue"] = details.get("cpu_ms_ue", 0.0)
    record["cpu_ms_ap2"] = (handover_result or {}).get("cpu_ms_ap", 0.0)
    record["processing_ms_ap2"] = (handover_result or {}).get("processing_ms_ap", 0.0)
    record["ts5"] = access_result.get("ts1", "")
    record["ts6"] = handover_result.get("ts2", "") if handover_result else ""

    return record, status == "ok"


def run_static_scenario(
    *,
    args: argparse.Namespace,
    config: Dict,
    writer: csv.DictWriter,
    out_fh,
    summary: Dict[Tuple, Dict[str, int]],
) -> None:
    ue_cfg = config["ue_ap2"]
    helper_cfg = config.get("ue_ap1", {})
    backhaul_cfg = config.get("ap_backhaul", {})

    ue_rtts = iter_values(ue_cfg.get("rtt_ms", []))
    ue_jitter = iter_values(ue_cfg.get("jitter_ms", 0.0))
    ue_loss = iter_values(ue_cfg.get("loss_pct", 0.0))

    helper_rtt_values = iter_values(helper_cfg.get("rtt_ms", [0.0]))
    helper_jitter_values = iter_values(helper_cfg.get("jitter_ms", 0.0))
    helper_loss_values = iter_values(helper_cfg.get("loss_pct", 0.0))

    backhaul_rtt_values = iter_values(backhaul_cfg.get("rtt_ms", [0.0]))
    backhaul_jitter_values = iter_values(backhaul_cfg.get("jitter_ms", 0.0))
    backhaul_loss_values = iter_values(backhaul_cfg.get("loss_pct", 0.0))

    timeouts = config.get("timeouts_ms", [args.timeout_ms])
    pto_values = config.get("pto", [args.pto])
    runs = int(config.get("runs", 1))

    scenario_name = config.get("name", "scenario")
    mode = config.get("mode", "LEO_ONLY")

    for rtt in ue_rtts:
        for jitter in ue_jitter:
            for loss in ue_loss:
                for helper_r in helper_rtt_values:
                    for helper_j in helper_jitter_values:
                        for helper_l in helper_loss_values:
                            for back_r in backhaul_rtt_values:
                                for back_j in backhaul_jitter_values:
                                    for back_l in backhaul_loss_values:
                                        for timeout_ms in timeouts:
                                            for pto in pto_values:
                                                key = (mode, rtt, jitter, loss, timeout_ms, pto)
                                                summary[key]["total"] += runs

                                                for run_index in range(1, runs + 1):
                                                    apply_netem(
                                                        "ue",
                                                        args.ue_interface,
                                                        rtt,
                                                        jitter,
                                                        loss,
                                                    )
                                                    apply_netem(
                                                        "ap2",
                                                        args.ap2_interface,
                                                        rtt,
                                                        jitter,
                                                        loss,
                                                    )
                                                    apply_netem(
                                                        "ue",
                                                        args.ue_helper_interface,
                                                        helper_r,
                                                        helper_j,
                                                        helper_l,
                                                    )
                                                    apply_netem(
                                                        "ap1",
                                                        args.ap1_interface,
                                                        helper_r,
                                                        helper_j,
                                                        helper_l,
                                                    )
                                                    apply_netem(
                                                        "ap2",
                                                        args.ap2_backhaul_interface,
                                                        back_r,
                                                        back_j,
                                                        back_l,
                                                    )
                                                    apply_netem(
                                                        "gm",
                                                        args.gm_interface,
                                                        back_r,
                                                        back_j,
                                                        back_l,
                                                    )

                                                    try:
                                                        access_result = run_access_client(
                                                            ue_id=args.ue_id,
                                                            timeout_ms=timeout_ms,
                                                            pto=pto,
                                                            context_path=args.context,
                                                            cache_dir=args.cache_dir,
                                                            ap_host="ap1",
                                                            ap_port=6000,
                                                        )
                                                        if access_result.get("status") == "ok":
                                                            handover_result = run_handover_client(
                                                                ue_id=args.ue_id,
                                                                timeout_ms=timeout_ms,
                                                                pto=pto,
                                                                context_path=args.context,
                                                                cache_dir=args.cache_dir,
                                                                ap_host="ap2",
                                                                ap_port=7000,
                                                                target_ap_id="AP-02",
                                                            )
                                                        else:
                                                            handover_result = {
                                                                "status": "skipped",
                                                                "failed_stage": "handover_skipped",
                                                                "errno": 0,
                                                                "attempts": 0,
                                                                "latency_ms": 0.0,
                                                                "bytes_online": 0,
                                                                "msgs_online": 0,
                                                                "cpu_ms_ue": 0.0,
                                                                "cpu_ms_ap": 0.0,
                                                                "ts1": access_result.get("ts1", ""),
                                                                "ts2": "",
                                                            }
                                                    finally:
                                                        clear_netem("ue", args.ue_interface)
                                                        clear_netem("ap2", args.ap2_interface)
                                                        clear_netem("ue", args.ue_helper_interface)
                                                        clear_netem("ap1", args.ap1_interface)
                                                        clear_netem("ap2", args.ap2_backhaul_interface)
                                                        clear_netem("gm", args.gm_interface)

                                                    extra = {}
                                                    record, is_ok = build_result_record(
                                                        fieldnames=writer.fieldnames,
                                                        scenario=scenario_name,
                                                        mode=mode,
                                                        rtt_ms=rtt,
                                                        loss_pct=loss,
                                                        timeout_ms=timeout_ms,
                                                        pto=pto,
                                                        run_index=run_index,
                                                        access_result=access_result,
                                                        handover_result=handover_result,
                                                        extra=extra,
                                                    )

                                                    if is_ok:
                                                        summary[key]["success"] += 1

                                                    writer.writerow(record)
                                                    out_fh.flush()


def run_rain_fade_scenario(
    *,
    args: argparse.Namespace,
    config: Dict,
    writer: csv.DictWriter,
    out_fh,
    summary: Dict[Tuple, Dict[str, int]],
) -> None:
    target_cfg = config["ue_ap2"]
    helper_cfg = config.get("ue_ap1", {})
    backhaul_cfg = config.get("ap_backhaul", {})

    base_rtts_raw = target_cfg.get("base_rtt_ms", [])
    if not isinstance(base_rtts_raw, list):
        base_rtts_raw = [base_rtts_raw]
    base_rtts = [float(x) for x in base_rtts_raw]

    states = target_cfg.get("states", {})
    if not states:
        raise ValueError("RAIN_FADE mode requires states under ue_ap2 configuration")

    base_jitter = float(target_cfg.get("jitter_ms", 0.0))
    step_ms = int(target_cfg.get("ge_step_ms", 50))
    base_down_mbps = float(target_cfg.get("base_down_mbps", 100.0))
    base_up_mbps = float(target_cfg.get("base_up_mbps", 20.0))
    downlink_only = bool(target_cfg.get("downlink_only", False))
    queue_limit = target_cfg.get("queue_limit")
    default_bad_jitter_extra = float(target_cfg.get("bad_jitter_extra_ms", 0.0))
    seed_base = target_cfg.get("seed")

    helper_states = helper_cfg.get("states", {})
    helper_base_rtts = helper_cfg.get("base_rtt_ms", base_rtts)
    if helper_base_rtts is None:
        helper_base_rtts = base_rtts
    if not isinstance(helper_base_rtts, list):
        helper_base_rtts = [helper_base_rtts]
    helper_base_rtts = [float(x) for x in helper_base_rtts] or base_rtts
    helper_base_jitter = float(helper_cfg.get("jitter_ms", base_jitter))
    helper_base_down = float(helper_cfg.get("base_down_mbps", base_down_mbps))
    helper_base_up = float(helper_cfg.get("base_up_mbps", base_up_mbps))

    backhaul_rtts = [float(x) for x in iter_values(backhaul_cfg.get("rtt_ms", [0.0]))]
    backhaul_jitter = [float(x) for x in iter_values(backhaul_cfg.get("jitter_ms", 0.0))]
    backhaul_loss = [float(x) for x in iter_values(backhaul_cfg.get("loss_pct", 0.0))]

    timeouts = config.get("timeouts_ms", [args.timeout_ms])
    pto_values = config.get("pto", [args.pto])
    runs = int(config.get("runs", 1))
    scenario_name = config.get("name", "scenario")
    mode = config.get("mode", "RAIN_FADE").upper()

    state_offsets = {name: idx * 10_000 for idx, name in enumerate(states.keys())}
    helper_state_offsets = {name: idx * 10_000 for idx, name in enumerate(helper_states.keys())}
    helper_rtt_count = len(helper_base_rtts) or 1

    for rtt_index, base_rtt in enumerate(base_rtts):
        helper_rtt = float(helper_base_rtts[rtt_index % helper_rtt_count] if helper_base_rtts else base_rtt)
        for profile_name, profile_cfg in states.items():
            bw_factor = float(profile_cfg.get("bw_factor", 1.0))
            down_rate = base_down_mbps * bw_factor
            up_rate = base_up_mbps * bw_factor
            loss_good = float(profile_cfg.get("loss_good", 0.0))
            loss_bad = float(profile_cfg.get("loss_bad", loss_good))
            p_gb = float(profile_cfg.get("p_gb", 0.0))
            p_bg = float(profile_cfg.get("p_bg", 0.0))
            bad_jitter_extra = float(profile_cfg.get("jitter_bad_extra_ms", default_bad_jitter_extra))
            micro_cfg = profile_cfg.get("micro_blackout")
            if isinstance(micro_cfg, str) and micro_cfg.lower() in {"off", "none"}:
                micro_cfg = None

            helper_profile_cfg = helper_states.get(profile_name, {})
            helper_loss_good = float(helper_profile_cfg.get("loss_good", profile_cfg.get("loss_good", loss_good)))
            helper_bw_factor = float(helper_profile_cfg.get("bw_factor", bw_factor))
            helper_down_rate = helper_base_down * helper_bw_factor
            helper_up_rate = helper_base_up * helper_bw_factor

            for back_r in backhaul_rtts:
                for back_j in backhaul_jitter:
                    for back_l in backhaul_loss:
                        for timeout_ms in timeouts:
                            for pto in pto_values:
                                key = (mode, profile_name, base_rtt, timeout_ms, pto)
                                summary[key]["total"] += runs

                                for run_index in range(1, runs + 1):
                                    apply_netem(
                                        "ue",
                                        args.ue_helper_interface,
                                        helper_rtt,
                                        helper_base_jitter,
                                        helper_loss_good,
                                        rate_mbps=helper_up_rate,
                                    )
                                    apply_netem(
                                        "ap1",
                                        args.ap1_interface,
                                        helper_rtt,
                                        helper_base_jitter,
                                        helper_loss_good,
                                        rate_mbps=helper_down_rate,
                                    )
                                    apply_netem(
                                        "ap2",
                                        args.ap2_backhaul_interface,
                                        back_r,
                                        back_j,
                                        back_l,
                                    )
                                    apply_netem(
                                        "gm",
                                        args.gm_interface,
                                        back_r,
                                        back_j,
                                        back_l,
                                    )

                                    seed = None
                                    if seed_base is not None:
                                        seed = int(
                                            seed_base
                                            + state_offsets.get(profile_name, 0)
                                            + helper_state_offsets.get(profile_name, 0)
                                            + (rtt_index * 100)
                                            + (timeout_ms * 5)
                                            + run_index
                                        )

                                    controller = RainFadeController(
                                        apply_netem=apply_netem,
                                        ue_container="ue",
                                        ue_interface=args.ue_interface,
                                        leo2_container="ap2",
                                        leo2_interface=args.ap2_interface,
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
                                        micro_blackout=micro_cfg,
                                    )

                                    controller.start()
                                    metrics_data: Dict[str, Any] = {}
                                    try:
                                        access_result = run_access_client(
                                            ue_id=args.ue_id,
                                            timeout_ms=timeout_ms,
                                            pto=pto,
                                            context_path=args.context,
                                            cache_dir=args.cache_dir,
                                            ap_host="ap1",
                                            ap_port=6000,
                                        )
                                        if access_result.get("status") == "ok":
                                            handover_result = run_handover_client(
                                                ue_id=args.ue_id,
                                                timeout_ms=timeout_ms,
                                                pto=pto,
                                                context_path=args.context,
                                                cache_dir=args.cache_dir,
                                                ap_host="ap2",
                                                ap_port=7000,
                                                target_ap_id="AP-02",
                                            )
                                        else:
                                            handover_result = {
                                                "status": "skipped",
                                                "failed_stage": "handover_skipped",
                                                "errno": 0,
                                                "attempts": 0,
                                                "latency_ms": 0.0,
                                                "bytes_online": 0,
                                                "msgs_online": 0,
                                                "cpu_ms_ue": 0.0,
                                                "cpu_ms_ap": 0.0,
                                                "ts1": access_result.get("ts1", ""),
                                                "ts2": "",
                                            }
                                        metrics_data = controller.snapshot()
                                    finally:
                                        controller.stop()
                                        clear_netem("ue", args.ue_interface)
                                        clear_netem("ap2", args.ap2_interface)
                                        clear_netem("ue", args.ue_helper_interface)
                                        clear_netem("ap1", args.ap1_interface)
                                        clear_netem("ap2", args.ap2_backhaul_interface)
                                        clear_netem("gm", args.gm_interface)

                                    extra = {
                                        "rain_profile": profile_name,
                                        "bw_factor": metrics_data.get("bw_factor", bw_factor),
                                        "down_rate_mbps": metrics_data.get("down_rate_mbps", down_rate),
                                        "up_rate_mbps": metrics_data.get("up_rate_mbps", up_rate),
                                        "bad_ticks": metrics_data.get("bad_ticks", ""),
                                        "total_ticks": metrics_data.get("total_ticks", ""),
                                        "bad_ratio": metrics_data.get("bad_ratio", ""),
                                        "blackout_events": metrics_data.get("blackout_events", ""),
                                        "blackout_ticks": metrics_data.get("blackout_ticks", ""),
                                    }

                                    record, is_ok = build_result_record(
                                        fieldnames=writer.fieldnames,
                                        scenario=scenario_name,
                                        mode=mode,
                                        rtt_ms=base_rtt,
                                        loss_pct=loss_good,
                                        timeout_ms=timeout_ms,
                                        pto=pto,
                                        run_index=run_index,
                                        access_result=access_result,
                                        handover_result=handover_result,
                                        extra=extra,
                                    )

                                    if is_ok:
                                        summary[key]["success"] += 1

                                    writer.writerow(record)
                                    out_fh.flush()


def run_short_window_scenario(
    *,
    args: argparse.Namespace,
    config: Dict,
    writer: csv.DictWriter,
    out_fh,
    summary: Dict[Tuple, Dict[str, int]],
) -> None:
    window_cfg = config["ue_ap2"]
    helper_cfg = config.get("ue_ap1", {})
    backhaul_cfg = config.get("ap_backhaul", {})

    base_rtts_raw = window_cfg.get("rtt_ms", [])
    if not isinstance(base_rtts_raw, list):
        base_rtts_raw = [base_rtts_raw]
    base_rtts = [float(x) for x in base_rtts_raw]

    jitter_ms = float(window_cfg.get("jitter_ms", 0.0))
    loss_pct_base = float(window_cfg.get("loss_pct", 0.0))
    loss_pct_window = float(window_cfg.get("loss_pct_window", loss_pct_base))
    base_down_mbps = float(window_cfg.get("base_down_mbps", 100.0))
    base_up_mbps = float(window_cfg.get("base_up_mbps", 20.0))
    window_profiles = window_cfg.get("window_profiles", {})
    if not window_profiles:
        raise ValueError("SHORT_WINDOW mode requires window_profiles under ue_ap2 configuration")
    step_ms = int(window_cfg.get("window_step_ms", 100))
    uplink_delay_range = window_cfg.get("uplink_delay_ms", (0, 0))
    downlink_ready_range = window_cfg.get("downlink_ready_delay_ms", (0, 0))
    guard_close_range = window_cfg.get("guard_close_ms")
    micro_cfg = window_cfg.get("micro_blackout")

    helper_rtt_base = float(first_value(helper_cfg.get("rtt_ms", base_rtts[0] if base_rtts else 0.0)))
    helper_jitter_base = float(first_value(helper_cfg.get("jitter_ms", jitter_ms)))
    helper_loss_base = float(first_value(helper_cfg.get("loss_pct", loss_pct_base)))
    helper_down_rate = float(helper_cfg.get("base_down_mbps", base_down_mbps))
    helper_up_rate = float(helper_cfg.get("base_up_mbps", base_up_mbps))

    backhaul_rtt = float(first_value(backhaul_cfg.get("rtt_ms", 0.0)))
    backhaul_jitter = float(first_value(backhaul_cfg.get("jitter_ms", 0.0)))
    backhaul_loss = float(first_value(backhaul_cfg.get("loss_pct", 0.0)))

    apply_netem(
        "ue",
        args.ue_helper_interface,
        helper_rtt_base,
        helper_jitter_base,
        helper_loss_base,
        rate_mbps=helper_up_rate,
    )
    apply_netem(
        "ap1",
        args.ap1_interface,
        helper_rtt_base,
        helper_jitter_base,
        helper_loss_base,
        rate_mbps=helper_down_rate,
    )
    apply_netem(
        "ap2",
        args.ap2_backhaul_interface,
        backhaul_rtt,
        backhaul_jitter,
        backhaul_loss,
    )
    apply_netem(
        "gm",
        args.gm_interface,
        backhaul_rtt,
        backhaul_jitter,
        backhaul_loss,
    )

    timeouts = config.get("timeouts_ms", [args.timeout_ms])
    pto_values = config.get("pto", [args.pto])
    runs = int(config.get("runs", 1))
    scenario_name = config.get("name", "scenario")
    mode = config.get("mode", "SHORT_WINDOW").upper()

    for base_rtt in base_rtts:
        apply_netem(
            "ue",
            args.ue_interface,
            base_rtt,
            jitter_ms,
            loss_pct_base,
            rate_mbps=base_up_mbps,
        )
        apply_netem(
            "ap2",
            args.ap2_interface,
            base_rtt,
            jitter_ms,
            loss_pct_base,
            rate_mbps=base_down_mbps,
        )

        controller = WindowController(
            ue_container="ue",
            ue_interface=args.ue_interface,
            leo2_container="ap2",
            leo2_interface=args.ap2_interface,
        )

        try:
            for profile_name, profile_cfg in window_profiles.items():
                duration_min = float(profile_cfg["duration_min_s"])
                duration_max = float(profile_cfg["duration_max_s"])

                for timeout_ms in timeouts:
                    for pto in pto_values:
                        key = (mode, profile_name, base_rtt, timeout_ms, pto)
                        summary[key]["total"] += runs

                        for run_index in range(1, runs + 1):
                            record = {field: "" for field in writer.fieldnames}
                            record.update(
                                {
                                    "scenario": scenario_name,
                                    "mode": mode,
                                    "rtt_ms": base_rtt,
                                    "jitter_ms": jitter_ms,
                                    "loss_pct": loss_pct_base,
                                    "helper_rtt_ms": helper_rtt_base,
                                    "helper_jitter_ms": helper_jitter_base,
                                    "helper_loss_pct": helper_loss_base,
                                    "backhaul_rtt_ms": backhaul_rtt,
                                    "backhaul_jitter_ms": backhaul_jitter,
                                    "backhaul_loss_pct": backhaul_loss,
                                    "timeout_ms": timeout_ms,
                                    "pto": pto,
                                    "run": run_index,
                                    "window_profile": profile_name,
                                }
                            )
                            access_result: Dict[str, Any] = {}
                            handover_result: Dict[str, Any] = {}

                            full_window_ms = int(round(random.uniform(duration_min, duration_max) * 1000))
                            guard_ms = 0
                            if isinstance(guard_close_range, (list, tuple)) and len(guard_close_range) == 2:
                                guard_ms = int(round(random.uniform(guard_close_range[0], guard_close_range[1])))
                            elif guard_close_range:
                                guard_ms = int(round(float(guard_close_range)))
                            guard_ms = max(0, guard_ms)
                            usable_ms = max(step_ms, full_window_ms - guard_ms)

                            controller.close()
                            window_loss_active = False
                            blackout_timers: List[threading.Timer] = []
                            scheduled_blackouts = 0

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
                                    "ap2",
                                    args.ap2_interface,
                                    base_rtt,
                                    jitter_ms,
                                    loss_pct_window,
                                    rate_mbps=base_down_mbps,
                                )
                                window_loss_active = True

                                controller.open_for(usable_ms / 1000.0)

                                down_ready_ms = 0
                                if isinstance(downlink_ready_range, (list, tuple)) and len(downlink_ready_range) == 2:
                                    down_ready_ms = int(
                                        round(random.uniform(downlink_ready_range[0], downlink_ready_range[1]))
                                    )
                                elif downlink_ready_range:
                                    down_ready_ms = int(round(float(downlink_ready_range)))
                                down_ready_ms = max(0, down_ready_ms)
                                if down_ready_ms > 0:
                                    controller.drop_downlink_for(down_ready_ms)

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
                                            scheduled_blackouts += 1
                                            start_ms += blackout_ms
                                        else:
                                            start_ms += step_ms

                                if isinstance(uplink_delay_range, (list, tuple)) and len(uplink_delay_range) == 2:
                                    uplink_delay_ms = int(
                                        round(random.uniform(uplink_delay_range[0], uplink_delay_range[1]))
                                    )
                                elif uplink_delay_range:
                                    uplink_delay_ms = int(round(float(uplink_delay_range)))
                                else:
                                    uplink_delay_ms = 0
                                uplink_delay_ms = max(0, uplink_delay_ms)

                                record["guard_close_ms"] = guard_ms
                                record["uplink_delay_ms"] = uplink_delay_ms
                                record["down_ready_ms"] = down_ready_ms
                                record["scheduled_blackouts"] = scheduled_blackouts
                                record["window_duration_ms"] = usable_ms

                                if uplink_delay_ms > 0:
                                    time.sleep(uplink_delay_ms / 1000.0)

                                access_result = run_access_client(
                                    ue_id=args.ue_id,
                                    timeout_ms=timeout_ms,
                                    pto=pto,
                                    context_path=args.context,
                                    cache_dir=args.cache_dir,
                                    ap_host="ap1",
                                    ap_port=6000,
                                )
                                record["access_status"] = access_result.get("status", "")
                                record["access_latency_ms"] = access_result.get("latency_ms", "")

                                if access_result.get("status") == "ok":
                                    handover_result = run_handover_client(
                                        ue_id=args.ue_id,
                                        timeout_ms=timeout_ms,
                                        pto=pto,
                                        context_path=args.context,
                                        cache_dir=args.cache_dir,
                                        ap_host="ap2",
                                        ap_port=7000,
                                        target_ap_id="AP-02",
                                    )
                                else:
                                    handover_result = {
                                        "status": "skipped",
                                        "failed_stage": "handover_skipped",
                                        "errno": 0,
                                        "attempts": 0,
                                        "latency_ms": 0.0,
                                        "bytes_online": 0,
                                        "msgs_online": 0,
                                        "cpu_ms_ue": 0.0,
                                        "cpu_ms_ap": 0.0,
                                        "ts1": access_result.get("ts1", ""),
                                        "ts2": "",
                                    }

                                record["handover_status"] = handover_result.get("status", "")
                                record["handover_latency_ms"] = handover_result.get("latency_ms", "")

                                controller.wait_for_close()
                                for timer_obj in blackout_timers:
                                    timer_obj.cancel()

                                metrics = controller.metrics()
                                if metrics.last_window_ms:
                                    record["window_duration_ms"] = metrics.last_window_ms

                            finally:
                                if window_loss_active:
                                    apply_netem(
                                        "ue",
                                        args.ue_interface,
                                        base_rtt,
                                        jitter_ms,
                                        loss_pct_base,
                                        rate_mbps=base_up_mbps,
                                    )
                                    apply_netem(
                                        "ap2",
                                        args.ap2_interface,
                                        base_rtt,
                                        jitter_ms,
                                        loss_pct_base,
                                        rate_mbps=base_down_mbps,
                                    )

                            extra = {
                                "window_profile": record.get("window_profile", profile_name),
                                "window_duration_ms": record.get("window_duration_ms", ""),
                                "uplink_delay_ms": record.get("uplink_delay_ms", ""),
                                "down_ready_ms": record.get("down_ready_ms", ""),
                                "guard_close_ms": record.get("guard_close_ms", ""),
                                "scheduled_blackouts": record.get("scheduled_blackouts", ""),
                            }

                            output_record, is_ok = build_result_record(
                                fieldnames=writer.fieldnames,
                                scenario=scenario_name,
                                mode=mode,
                                rtt_ms=base_rtt,
                                loss_pct=loss_pct_window,
                                timeout_ms=timeout_ms,
                                pto=pto,
                                run_index=run_index,
                                access_result=access_result,
                                handover_result=handover_result,
                                extra=extra,
                            )

                            if is_ok:
                                summary[key]["success"] += 1

                            writer.writerow(output_record)
                            out_fh.flush()
        finally:
            controller.shutdown()
            clear_netem("ue", args.ue_interface)
            clear_netem("ap2", args.ap2_interface)

    clear_netem("ue", args.ue_helper_interface)
    clear_netem("ap1", args.ap1_interface)
    clear_netem("ap2", args.ap2_backhaul_interface)
    clear_netem("gm", args.gm_interface)

def main() -> None:
    parser = argparse.ArgumentParser(description="Run Liu2022 authentication scenarios")
    parser.add_argument("--config", type=Path, required=True, help="YAML configuration path")
    parser.add_argument("--context", type=Path, default=DEFAULT_CONTEXT_HOST_PATH, help="Offline context path")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_HOST_PATH, help="Runtime cache directory")
    parser.add_argument("--output", type=Path, default=Path("results_liu2022.csv"), help="CSV output path")
    parser.add_argument("--ue-id", default="ue-001", help="UE identifier to test")
    parser.add_argument("--timeout-ms", type=int, default=300, help="Default timeout if config omits it")
    parser.add_argument("--pto", type=int, default=2, help="Default PTO if config omits it")
    parser.add_argument("--ue-interface", default="eth0", help="UE interface towards target AP (ap2)")
    parser.add_argument("--ue-helper-interface", default="eth1", help="UE interface towards helper AP (ap1)")
    parser.add_argument("--ap1-interface", default="eth0", help="AP1 interface towards UE")
    parser.add_argument("--ap2-interface", default="eth0", help="AP2 interface towards UE")
    parser.add_argument("--ap2-backhaul-interface", default="eth1", help="AP2 interface towards GM")
    parser.add_argument("--gm-interface", default="eth0", help="GM interface towards APs")
    parser.add_argument(
        "--disable-netem",
        action="store_true",
        help="Skip Docker tc/netem configuration (useful when Docker socket access is unavailable)",
    )
    args = parser.parse_args()

    if args.disable_netem:
        global _NETEM_REQUESTED, _NETEM_AVAILABLE
        _NETEM_REQUESTED = False
        _NETEM_AVAILABLE = False
        print("[LIU2022] Running without netem (--disable-netem).", file=sys.stderr)

    args.context = args.context.resolve()
    args.cache_dir = args.cache_dir.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with args.config.open("r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh)

    mode = config.get("mode", "LEO_ONLY").upper()
    summary: Dict[Tuple, Dict[str, int]] = defaultdict(lambda: {"total": 0, "success": 0})

    with args.output.open("w", newline="", encoding="utf-8") as out_fh:
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
            "cpu_ms_ap2",
            "processing_ms_ap2",
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

        if mode == "LEO_ONLY":
            run_static_scenario(
                args=args,
                config=config,
                writer=writer,
                out_fh=out_fh,
                summary=summary,
            )
        elif mode == "RAIN_FADE":
            run_rain_fade_scenario(
                args=args,
                config=config,
                writer=writer,
                out_fh=out_fh,
                summary=summary,
            )
        elif mode == "SHORT_WINDOW":
            run_short_window_scenario(
                args=args,
                config=config,
                writer=writer,
                out_fh=out_fh,
                summary=summary,
            )
        else:
            raise NotImplementedError(f"mode {mode} not yet supported in Liu2022 orchestrator")

    for key, stats in summary.items():
        total = stats["total"]
        success = stats["success"]
        rate = (success / total * 100.0) if total else 0.0
        print(f"{key}: success {success}/{total} ({rate:.2f}%)")


if __name__ == "__main__":
    main()
