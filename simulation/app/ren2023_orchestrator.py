#!/usr/bin/env python3
"""Scenario runner for REN2023 single-direction handover experiments."""

from __future__ import annotations

import argparse
import csv
import copy
import itertools
import json
import math
import random
import subprocess
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

APP_PATH = Path(__file__).resolve().parent
if str(APP_PATH) not in sys.path:
    sys.path.insert(0, str(APP_PATH))

from rain_fade import RainFadeController
from window_controller import WindowController

DEFAULT_CONTEXT_HOST_PATH = Path(__file__).resolve().parents[1] / "shared" / "offline_context_ren2023.pkl"
DEFAULT_CONTEXT_CONTAINER_PATH = Path("/shared/offline_context_ren2023.pkl")

FIELDNAMES = [
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
    "cpu_ms_ground",
    "cpu_ms_ncc",
    "processing_ms_leo2",
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
    "combo_index",
]

_HTB_ROOT_READY: Dict[Tuple[str, str], bool] = {}
_HTB_RATE_CACHE: Dict[Tuple[str, str], float] = {}
_HTB_NETEM_READY: Dict[Tuple[str, str], bool] = {}
_SIMPLE_NETEM_READY: Dict[Tuple[str, str], bool] = {}
_NETEM_CONFIG_CACHE: Dict[Tuple[str, str], Tuple[float, float, float, float | None, int | None]] = {}
_INFRA_STAGE_PREFIXES = ("netem_error", "rain_controller_error")
MAX_INFRA_RETRIES = 3


def run_command(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def emit_container_output(label: str, stdout: str, stderr: str) -> None:
    if stdout:
        for line in stdout.splitlines():
            print(f"[{label}] {line}", flush=True)
    if stderr:
        for line in stderr.splitlines():
            print(f"[{label}][stderr] {line}", flush=True)


def ensure_containers_running(containers: Iterable[str]) -> None:
    missing: List[str] = []
    for name in containers:
        if not name:
            continue
        # Treat non-resolvable hostnames as missing containers
        try:
            subprocess.run(
                ["docker", "inspect", "-f", "{{.Name}}", name],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:  # pragma: no cover
            raise RuntimeError("Docker binary not available") from exc
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
            "Required docker containers are not running: " + ", ".join(missing)
        )


def apply_netem(
    container: str,
    interface: str,
    rtt_ms: float,
    jitter_ms: float,
    loss_pct: float,
    *,
    rate_mbps: float | None = None,
    limit_packets: int | None = None,
) -> None:
    delay_ms = rtt_ms / 2.0
    netem_args = _build_netem_args(delay_ms, jitter_ms, loss_pct, limit_packets)
    rate_value = None if rate_mbps is None else max(rate_mbps, 0.001)
    key = _netem_key(container, interface)
    state = (
        round(delay_ms, 6),
        round(jitter_ms or 0.0, 6),
        round(loss_pct, 6),
        round(rate_value, 6) if rate_value is not None else None,
        int(limit_packets) if limit_packets is not None else None,
    )
    if _NETEM_CONFIG_CACHE.get(key) == state:
        return
    if rate_value is None:
        _apply_simple_netem(container, interface, netem_args, key)
    else:
        _apply_htb_netem(container, interface, netem_args, rate_value)
    _NETEM_CONFIG_CACHE[key] = state


def _netem_key(container: str, interface: str) -> Tuple[str, str]:
    return (container or "", interface or "")


def _build_netem_args(
    delay_ms: float,
    jitter_ms: float,
    loss_pct: float,
    limit_packets: int | None,
) -> List[str]:
    args: List[str] = ["delay", f"{delay_ms:.3f}ms"]
    if jitter_ms and jitter_ms > 0:
        args.append(f"{jitter_ms:.3f}ms")
    loss_value = max(loss_pct, 0.0) if loss_pct is not None else 0.0
    args.extend(["loss", f"{loss_value:.4f}%"])
    if limit_packets:
        args.extend(["limit", str(limit_packets)])
    return args


def _is_infra_stage(stage: Optional[str]) -> bool:
    if not stage:
        return False
    return any(stage.startswith(prefix) for prefix in _INFRA_STAGE_PREFIXES)


def _run_netem_with_retries(container: str, interface: str, cmd: List[str]) -> None:
    last_error: subprocess.CalledProcessError | None = None
    for _ in range(3):
        try:
            run_command(cmd)
            return
        except subprocess.CalledProcessError as exc:
            last_error = exc
            clear_cmd = [
                "docker",
                "exec",
                container,
                "tc",
                "qdisc",
                "del",
                "dev",
                interface,
                "root",
            ]
            subprocess.run(clear_cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(0.05)
    if last_error is not None:
        raise last_error


def _apply_simple_netem(
    container: str,
    interface: str,
    netem_args: List[str],
    key: Tuple[str, str],
) -> None:
    if _SIMPLE_NETEM_READY.get(key):
        change_cmd = [
            "docker",
            "exec",
            container,
            "tc",
            "qdisc",
            "change",
            "dev",
            interface,
            "root",
            "netem",
            *netem_args,
        ]
        try:
            run_command(change_cmd)
            return
        except subprocess.CalledProcessError:
            _SIMPLE_NETEM_READY[key] = False
    replace_cmd = [
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
        *netem_args,
    ]
    _run_netem_with_retries(container, interface, replace_cmd)
    _SIMPLE_NETEM_READY[key] = True


def _ensure_htb_root(container: str, interface: str) -> None:
    cmd = [
        "docker",
        "exec",
        container,
        "tc",
        "qdisc",
        "replace",
        "dev",
        interface,
        "root",
        "handle",
        "1:",
        "htb",
        "default",
        "10",
    ]
    run_command(cmd)


def _configure_htb_class(container: str, interface: str, rate_str: str, burst_bytes: int) -> None:
    cmd = [
        "docker",
        "exec",
        container,
        "tc",
        "class",
        "replace",
        "dev",
        interface,
        "parent",
        "1:",
        "classid",
        "1:10",
        "htb",
        "rate",
        rate_str,
        "ceil",
        rate_str,
        "burst",
        str(burst_bytes),
        "cburst",
        str(burst_bytes),
    ]
    run_command(cmd)


def _apply_htb_netem(
    container: str,
    interface: str,
    netem_args: List[str],
    rate_value: float,
) -> None:
    key = _netem_key(container, interface)
    rate_str = f"{rate_value:.3f}Mbit"
    burst_bytes = max(int(rate_value * 1024), 1500)
    last_error: subprocess.CalledProcessError | None = None
    netem_cmd: List[str] = []
    for _ in range(3):
        try:
            if not _HTB_ROOT_READY.get(key):
                _ensure_htb_root(container, interface)
                _HTB_ROOT_READY[key] = True
                _HTB_RATE_CACHE.pop(key, None)
            if _HTB_RATE_CACHE.get(key) != rate_value:
                _configure_htb_class(container, interface, rate_str, burst_bytes)
                _HTB_RATE_CACHE[key] = rate_value
            op = "change" if _HTB_NETEM_READY.get(key) else "replace"
            netem_cmd = [
                "docker",
                "exec",
                container,
                "tc",
                "qdisc",
                op,
                "dev",
                interface,
                "parent",
                "1:10",
                "handle",
                "10:",
                "netem",
                *netem_args,
            ]
            run_command(netem_cmd)
            _HTB_NETEM_READY[key] = True
            return
        except subprocess.CalledProcessError as exc:
            last_error = exc
            _HTB_ROOT_READY[key] = False
            _HTB_RATE_CACHE.pop(key, None)
            _HTB_NETEM_READY[key] = False
            clear_cmd = [
                "docker",
                "exec",
                container,
                "tc",
                "qdisc",
                "del",
                "dev",
                interface,
                "root",
            ]
            subprocess.run(clear_cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(0.05)
    if last_error is not None:
        raise last_error


def _classify_netem_failure(exc: Exception, container: str) -> str:
    message = str(exc).strip().replace("\n", " ")
    if isinstance(exc, RuntimeError) and message.lower().startswith("required docker containers are not running"):
        parts = message.split(":", 1)
        if len(parts) == 2 and parts[1].strip():
            return f"netem_missing:{parts[1].strip()}"
        return f"netem_missing:{container}"
    if not message:
        message = exc.__class__.__name__
    return f"netem_error:{container}:{message}"


def _try_apply_netem(
    container: str,
    interface: str,
    rtt_ms: float,
    jitter_ms: float,
    loss_pct: float,
    *,
    rate_mbps: float | None = None,
    limit_packets: int | None = None,
) -> str | None:
    try:
        apply_netem(
            container,
            interface,
            rtt_ms,
            jitter_ms,
            loss_pct,
            rate_mbps=rate_mbps,
            limit_packets=limit_packets,
        )
        return None
    except (RuntimeError, subprocess.CalledProcessError) as exc:  # type: ignore[attr-defined]
        return _classify_netem_failure(exc, container)


def clear_netem(container: str, interface: str) -> None:
    if not container:
        return
    subprocess.run(
        ["docker", "exec", container, "tc", "qdisc", "del", "dev", interface, "root"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    key = _netem_key(container, interface)
    _HTB_ROOT_READY.pop(key, None)
    _HTB_RATE_CACHE.pop(key, None)
    _HTB_NETEM_READY.pop(key, None)
    _SIMPLE_NETEM_READY.pop(key, None)
    _NETEM_CONFIG_CACHE.pop(key, None)


def ensure_context(context_path: Path) -> None:
    if context_path.exists():
        return
    cmd = [
        sys.executable,
        str(Path(__file__).resolve().parent / "ren2023_generate_context.py"),
        "--output",
        str(context_path),
    ]
    run_command(cmd)


def _as_list(value: Any) -> List[float]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [float(v) for v in value]
    return [float(value)]


def _scenario_type(config: Dict[str, Any]) -> str:
    links = config.get("links", {})
    if any(isinstance(cfg, dict) and "states" in cfg for cfg in links.values()):
        return "rain"
    if any(isinstance(cfg, dict) and "window_profiles" in cfg for cfg in links.values()):
        return "window"
    return "basic"


@dataclass
class LinkProfile:
    rtt_ms: float
    jitter_ms: float
    loss_pct: float


@dataclass
class ScenarioCombo:
    ter_link: LinkProfile
    uav_link: LinkProfile
    sat_link: LinkProfile
    metadata: Dict[str, Any]


def _basic_combos(links: Dict[str, Dict[str, Any]]) -> List[ScenarioCombo]:
    ter_cfg = links.get("ter_uavnew", {})
    uav_cfg = links.get("uavnew_sat", {})
    sat_cfg = links.get("sat_ncc", {})

    ter_opts = [
        LinkProfile(rtt, jitter, loss)
        for rtt, jitter, loss in itertools.product(
            _as_list(ter_cfg.get("rtt_ms", 0.0)) or [0.0],
            _as_list(ter_cfg.get("jitter_ms", 0.0)) or [0.0],
            _as_list(ter_cfg.get("loss_pct", 0.0)) or [0.0],
        )
    ]
    uav_opts = [
        LinkProfile(rtt, jitter, loss)
        for rtt, jitter, loss in itertools.product(
            _as_list(uav_cfg.get("rtt_ms", 0.0)) or [0.0],
            _as_list(uav_cfg.get("jitter_ms", 0.0)) or [0.0],
            _as_list(uav_cfg.get("loss_pct", 0.0)) or [0.0],
        )
    ]
    sat_opts = [
        LinkProfile(rtt, jitter, loss)
        for rtt, jitter, loss in itertools.product(
            _as_list(sat_cfg.get("rtt_ms", 0.0)) or [0.0],
            _as_list(sat_cfg.get("jitter_ms", 0.0)) or [0.0],
            _as_list(sat_cfg.get("loss_pct", 0.0)) or [0.0],
        )
    ]

    combos: List[ScenarioCombo] = []
    for ter_link in ter_opts:
        for uav_link in uav_opts:
            if not math.isclose(ter_link.rtt_ms, uav_link.rtt_ms, abs_tol=1e-6):
                continue
            if not math.isclose(ter_link.loss_pct, uav_link.loss_pct, abs_tol=1e-6):
                continue
            for sat_link in sat_opts:
                combos.append(ScenarioCombo(ter_link, uav_link, sat_link, metadata={}))
    return combos


def _rain_combos(links: Dict[str, Dict[str, Any]]) -> List[ScenarioCombo]:
    def _rain_options(cfg: Dict[str, Any]) -> List[Tuple[LinkProfile, Dict[str, Any]]]:
        base_rtts = _as_list(cfg.get("base_rtt_ms", cfg.get("rtt_ms", 0.0))) or [0.0]
        jitter = float(cfg.get("jitter_ms", 0.0))
        states = cfg.get("states", {})
        options: List[Tuple[LinkProfile, Dict[str, Any]]] = []
        for rtt in base_rtts:
            for state_name, state_cfg in states.items():
                loss_bad = float(state_cfg.get("loss_bad", state_cfg.get("loss_pct", 0.0)))
                options.append(
                    (
                        LinkProfile(rtt, jitter, loss_bad),
                        {
                            "state": str(state_name),
                            "bw_factor": float(state_cfg.get("bw_factor", 1.0)),
                            "loss_good": float(state_cfg.get("loss_good", loss_bad)),
                            "loss_bad": loss_bad,
                            "p_gb": float(state_cfg.get("p_gb", 0.0)),
                            "p_bg": float(state_cfg.get("p_bg", 0.0)),
                            "bad_jitter_extra_ms": float(cfg.get("bad_jitter_extra_ms", 0.0)),
                            "ge_step_ms": int(cfg.get("ge_step_ms", 100)),
                            "base_down_mbps": float(cfg.get("base_down_mbps", 0.0)),
                            "base_up_mbps": float(cfg.get("base_up_mbps", 0.0)),
                            "queue_limit": cfg.get("queue_limit"),
                            "downlink_only": bool(cfg.get("downlink_only", False)),
                            "seed": cfg.get("seed"),
                            "micro_blackout": state_cfg.get("micro_blackout"),
                        },
                    )
                )
        return options or [(LinkProfile(0.0, jitter, 0.0), {"state": "default", "bw_factor": 1.0})]

    def _single_options(cfg: Dict[str, Any]) -> List[Tuple[LinkProfile, Dict[str, Any]]]:
        rtts = _as_list(cfg.get("rtt_ms", 0.0)) or [0.0]
        jitters = _as_list(cfg.get("jitter_ms", 0.0)) or [0.0]
        losses = _as_list(cfg.get("loss_pct", 0.0)) or [0.0]
        return [
            (LinkProfile(rtt, jitter, loss), {})
            for rtt, jitter, loss in itertools.product(rtts, jitters, losses)
        ]

    ter_opts = _rain_options(links.get("ter_uavnew", {}))
    uav_opts = _rain_options(links.get("uavnew_sat", {}))
    sat_opts = _single_options(links.get("sat_ncc", {}))

    base_down = float(links.get("uavnew_sat", {}).get("base_down_mbps", 0.0))
    base_up = float(links.get("uavnew_sat", {}).get("base_up_mbps", 0.0))

    combos: List[ScenarioCombo] = []
    def _build_metadata(ter_info, uav_info, sat_info) -> ScenarioCombo:
        ter_link, ter_meta = ter_info
        uav_link, uav_meta = uav_info
        sat_link, sat_meta = sat_info
        bw_factor = ter_meta.get("bw_factor", 1.0) * uav_meta.get("bw_factor", 1.0)
        metadata = {
            "rain_profile": f"{ter_meta.get('state', 'default')}→{uav_meta.get('state', 'default')}",
            "bw_factor": round(bw_factor, 4),
            "down_rate_mbps": round(base_down * bw_factor, 3) if base_down else "",
            "up_rate_mbps": round(base_up * bw_factor, 3) if base_up else "",
            "rain_links": {
                "ter_uavnew": dict(ter_meta),
                "uavnew_sat": dict(uav_meta),
            },
        }
        metadata.update({k: v for k, v in sat_meta.items() if k not in metadata})
        return ScenarioCombo(ter_link, uav_link, sat_link, metadata=metadata)

    matched_combos: List[ScenarioCombo] = []
    def _states_match(ter_meta: Dict[str, Any], uav_meta: Dict[str, Any]) -> bool:
        ter_state = ter_meta.get("state")
        uav_state = uav_meta.get("state")
        if ter_state is None and uav_state is None:
            return True
        return ter_state == uav_state

    for ter_info in ter_opts:
        for uav_info in uav_opts:
            if not _states_match(ter_info[1], uav_info[1]):
                continue
            if not math.isclose(ter_info[0].rtt_ms, uav_info[0].rtt_ms, abs_tol=1e-6):
                continue
            for sat_info in sat_opts:
                matched_combos.append(_build_metadata(ter_info, uav_info, sat_info))

    if matched_combos:
        return matched_combos

    for ter_info in ter_opts:
        for uav_info in uav_opts:
            for sat_info in sat_opts:
                combos.append(_build_metadata(ter_info, uav_info, sat_info))
    return combos


def _init_rain_controller(
    link_name: str,
    link_profile: LinkProfile,
    link_meta: Dict[str, Any],
    *,
    ue_container: str,
    ue_interface: str,
    leo_container: str,
    leo_interface: str,
    combo_index: int,
    timeout_ms: int,
    pto: int,
    run_index: int,
) -> Tuple[Optional[RainFadeController], Optional[str]]:
    bw_factor = float(link_meta.get("bw_factor", 1.0))
    base_down = float(link_meta.get("base_down_mbps", 0.0))
    base_up = float(link_meta.get("base_up_mbps", 0.0))
    down_rate = base_down * bw_factor if base_down else 0.0
    up_rate = base_up * bw_factor if base_up else 0.0
    downlink_only = bool(link_meta.get("downlink_only", False))
    queue_limit = link_meta.get("queue_limit")
    if isinstance(queue_limit, (list, tuple)):
        queue_limit = queue_limit[0]
    seed = link_meta.get("seed")
    if seed is not None:
        seed = int(seed) + combo_index * 10_000 + int(timeout_ms) * 100 + int(pto) * 10 + run_index
    controller = RainFadeController(
        apply_netem=apply_netem,
        ue_container=ue_container,
        ue_interface=ue_interface,
        leo2_container=leo_container,
        leo2_interface=leo_interface,
        base_rtt_ms=link_profile.rtt_ms,
        base_jitter_ms=link_profile.jitter_ms,
        loss_good_pct=float(link_meta.get("loss_good", link_profile.loss_pct)),
        loss_bad_pct=float(link_meta.get("loss_bad", link_profile.loss_pct)),
        p_gb=float(link_meta.get("p_gb", 0.0)),
        p_bg=float(link_meta.get("p_bg", 0.0)),
        step_ms=int(link_meta.get("ge_step_ms", 100)),
        down_rate_mbps=down_rate,
        up_rate_mbps=up_rate,
        bw_factor=bw_factor,
        bad_jitter_extra_ms=float(link_meta.get("bad_jitter_extra_ms", 0.0)),
        queue_limit=int(queue_limit) if queue_limit is not None else None,
        downlink_only=downlink_only,
        seed=seed,
        micro_blackout=link_meta.get("micro_blackout"),
    )
    try:
        controller.start()
    except subprocess.CalledProcessError as exc:
        stage = _classify_netem_failure(exc, ue_container)
        controller.stop()
        return None, stage
    except Exception as exc:  # pragma: no cover - defensive
        controller.stop()
        return None, f"rain_controller_error:{link_name}:{exc.__class__.__name__}"
    return controller, None


def _start_rain_controllers(
    combo: ScenarioCombo,
    combo_index: int,
    args: argparse.Namespace,
    timeout_ms: int,
    pto: int,
    run_index: int,
    preflight_missing: List[str],
) -> Tuple[Dict[str, RainFadeController], Optional[str]]:
    if preflight_missing:
        return {}, f"netem_missing:{','.join(preflight_missing)}"
    rain_links = combo.metadata.get("rain_links", {})
    controllers: Dict[str, RainFadeController] = {}
    mappings = [
        (
            "ter_uavnew",
            combo.ter_link,
            args.ue_container,
            args.ue_interface,
            args.leo2_container,
            args.leo2_ue_interface,
        ),
        (
            "uavnew_sat",
            combo.uav_link,
            args.leo2_container,
            args.leo2_sat_interface,
            args.sat_container,
            args.sat_interface,
        ),
    ]
    for link_name, profile, ue_container, ue_interface, leo_container, leo_interface in mappings:
        link_meta = rain_links.get(link_name)
        if not link_meta:
            for ctrl in controllers.values():
                ctrl.stop()
            return {}, f"rain_meta_missing:{link_name}"
        controller, stage = _init_rain_controller(
            link_name,
            profile,
            link_meta,
            ue_container=ue_container,
            ue_interface=ue_interface,
            leo_container=leo_container,
            leo_interface=leo_interface,
            combo_index=combo_index,
            timeout_ms=timeout_ms,
            pto=pto,
            run_index=run_index,
        )
        if stage:
            for ctrl in controllers.values():
                ctrl.stop()
            return {}, stage
        controllers[link_name] = controller
    return controllers, None


def _collect_rain_metrics(controllers: Iterable[RainFadeController]) -> Dict[str, float]:
    if not controllers:
        return {}
    bad_ticks = 0
    total_ticks = 0
    blackout_events = 0
    blackout_ticks = 0
    blackout_active = False
    for ctrl in controllers:
        metrics = ctrl.metrics()
        bad_ticks += metrics.bad_ticks
        total_ticks += metrics.total_ticks
        blackout_events += metrics.blackout_events
        blackout_ticks += metrics.blackout_ticks
        blackout_active = blackout_active or metrics.blackout_active
    bad_ratio = (bad_ticks / total_ticks) if total_ticks else 0.0
    return {
        "bad_ticks": bad_ticks,
        "total_ticks": total_ticks,
        "bad_ratio": bad_ratio,
        "blackout_events": blackout_events,
        "blackout_ticks": blackout_ticks,
        "scheduled_blackouts": 1 if blackout_active else 0,
    }


def _start_window_controllers(
    combo: ScenarioCombo,
    args: argparse.Namespace,
    timeout_ms: int,
    pto: int,
    run_index: int,
    preflight_missing: List[str],
) -> Tuple[Dict[str, WindowController], Optional[str]]:
    if preflight_missing:
        return {}, f"netem_missing:{','.join(preflight_missing)}"

    controllers: Dict[str, WindowController] = {}
    window_links = combo.metadata.get("window_links", {})
    for link_name, profile, container_a, iface_a, container_b, iface_b in [
        ("ter_uavnew", combo.ter_link, args.ue_container, args.ue_interface, args.leo2_container, args.leo2_ue_interface),
        ("uavnew_sat", combo.uav_link, args.leo2_container, args.leo2_sat_interface, args.sat_container, args.sat_interface),
    ]:
        meta = window_links.get(link_name, {})
        try:
            controller = WindowController(
                container_a=container_a,
                interface_a=iface_a,
                container_b=container_b,
                interface_b=iface_b,
            )
            controllers[link_name] = controller
        except Exception as exc:  # pragma: no cover - defensive
            for ctrl in controllers.values():
                ctrl.shutdown()
            return {}, f"window_controller_error:{link_name}:{exc.__class__.__name__}"
    return controllers, None


def _sample_range(value: Any, *, default: float = 0.0) -> float:
    if isinstance(value, (list, tuple)):
        if not value:
            return default
        if len(value) == 1:
            return float(value[0])
        low, high = float(value[0]), float(value[1])
        if low > high:
            low, high = high, low
        return random.uniform(low, high)
    if value is None:
        return default
    return float(value)


def _prepare_window_run(
    combo: ScenarioCombo,
    args: argparse.Namespace,
    window_controllers: Dict[str, WindowController],
) -> Tuple[Optional[str], Dict[str, Any], Dict[str, Any], bool]:
    window_links = combo.metadata.get("window_links", {})
    if not window_links:
        return "window_meta_missing", {}, {}, False

    context: Dict[str, Any] = {"links": {}, "uplink_delay_ms": 0, "total_blackouts": 0}
    payload: Dict[str, Any] = {
        "window_profile": combo.metadata.get("window_profile", ""),
        "window_duration_ms": 0.0,
        "uplink_delay_ms": 0,
        "down_ready_ms": 0,
        "guard_close_ms": 0,
        "scheduled_blackouts": 0,
    }
    netem_applied = False

    link_definitions = {
        "ter_uavnew": {
            "profile": combo.ter_link,
            "pairs": [
                (args.ue_container, args.ue_interface, "up"),
                (args.leo2_container, args.leo2_ue_interface, "down"),
            ],
        },
        "uavnew_sat": {
            "profile": combo.uav_link,
            "pairs": [
                (args.leo2_container, args.leo2_sat_interface, "up"),
                (args.sat_container, args.sat_interface, "down"),
            ],
        },
    }

    for link_name, definition in link_definitions.items():
        controller = window_controllers.get(link_name)
        if controller is None:
            return f"window_controller_missing:{link_name}", {}, {}, netem_applied
        meta = window_links.get(link_name, {})
        profile = definition["profile"]
        base_loss = float(meta.get("loss_pct", profile.loss_pct))
        window_loss = float(meta.get("loss_pct_window", base_loss))
        jitter_ms = float(meta.get("jitter_ms", profile.jitter_ms))
        step_ms = int(meta.get("window_step_ms", 100))
        base_up = float(meta.get("base_up_mbps", 0.0))
        base_down = float(meta.get("base_down_mbps", 0.0))

        pairs_info = []
        for container, interface, direction in definition["pairs"]:
            rate = base_up if direction == "up" else base_down
            stage = _try_apply_netem(
                container,
                interface,
                profile.rtt_ms,
                jitter_ms,
                base_loss,
                rate_mbps=rate if rate else None,
            )
            if stage is not None:
                return stage, {}, {}, netem_applied
            pairs_info.append(
                {
                    "container": container,
                    "interface": interface,
                    "profile": profile,
                    "rate": rate,
                    "jitter_ms": jitter_ms,
                }
            )
            netem_applied = True

        controller.ensure_open()
        duration_cfg = meta.get("window_profiles", {}).get(meta.get("selected_profile", ""), {})
        duration_min_s = float(duration_cfg.get("duration_min_s", duration_cfg.get("duration_max_s", 0.0)))
        duration_max_s = float(duration_cfg.get("duration_max_s", duration_cfg.get("duration_min_s", 0.0)))
        if duration_max_s <= 0.0 and duration_min_s > 0.0:
            duration_max_s = duration_min_s
        full_window_ms = int(
            round(
                max(
                    step_ms,
                    (
                        random.uniform(duration_min_s, duration_max_s)
                        if duration_max_s > duration_min_s
                        else duration_min_s
                    )
                    * 1000.0,
                )
            )
        )
        guard_ms = int(round(max(0.0, _sample_range(meta.get("guard_close_ms"), default=0.0))))
        usable_ms = max(step_ms, full_window_ms - guard_ms)

        controller.close()
        for pair in pairs_info:
            stage = _try_apply_netem(
                pair["container"],
                pair["interface"],
                pair["profile"].rtt_ms,
                pair["jitter_ms"],
                window_loss,
                rate_mbps=pair["rate"] if pair["rate"] else None,
            )
            if stage is not None:
                return stage, {}, {}, netem_applied

        controller.open_for(usable_ms / 1000.0)

        down_ready_ms = int(
            round(
                max(
                    0.0,
                    _sample_range(meta.get("downlink_ready_delay_ms"), default=0.0),
                )
            )
        )
        if down_ready_ms > 0:
            controller.drop_downlink_for(down_ready_ms)

        uplink_delay_ms = int(
            round(
                max(
                    0.0,
                    _sample_range(meta.get("uplink_delay_ms"), default=0.0),
                )
            )
        )
        context["uplink_delay_ms"] = max(context["uplink_delay_ms"], uplink_delay_ms)
        if link_name == "ter_uavnew":
            payload["down_ready_ms"] = down_ready_ms
            payload["guard_close_ms"] = guard_ms
            payload["uplink_delay_ms"] = uplink_delay_ms

        micro_cfg = meta.get("micro_blackout")
        timers: List[threading.Timer] = []
        blackout_count = 0
        if micro_cfg:
            prob_per_s = _sample_range(micro_cfg.get("probability_per_s"), default=0.0)
            prob_per_tick = prob_per_s * (step_ms / 1000.0)

            duration_cfg = micro_cfg.get("duration_ms", 0.0)

            def sample_blackout_ms() -> int:
                value = _sample_range(duration_cfg, default=0.0)
                return int(round(max(step_ms, value)))

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
                    timers.append(timer_obj)
                    blackout_count += 1
                    start_ms += blackout_ms
                else:
                    start_ms += step_ms

        context["links"][link_name] = {
            "controller": controller,
            "pairs": pairs_info,
            "base_loss": base_loss,
            "window_loss": window_loss,
            "timers": timers,
            "down_ready_ms": down_ready_ms,
            "guard_ms": guard_ms,
            "usable_ms": usable_ms,
            "blackout_count": blackout_count,
            "window_loss_active": True,
        }
        context["total_blackouts"] += blackout_count

    payload["scheduled_blackouts"] = context["total_blackouts"]
    return None, context, payload, netem_applied


def _window_combos(links: Dict[str, Dict[str, Any]]) -> List[ScenarioCombo]:
    def _window_options(cfg: Dict[str, Any]) -> List[Tuple[LinkProfile, Dict[str, Any]]]:
        rtts = _as_list(cfg.get("rtt_ms", 0.0)) or [0.0]
        jitter = float(cfg.get("jitter_ms", 0.0))
        loss = float(cfg.get("loss_pct", 0.0))
        profiles = cfg.get("window_profiles", {})
        if not profiles:
            return [(LinkProfile(rtt, jitter, loss), {"profile": "default", "duration": 0.0}) for rtt in rtts]
        options: List[Tuple[LinkProfile, Dict[str, Any]]] = []
        for rtt in rtts:
            for profile_name, profile_cfg in profiles.items():
                options.append(
                    (
                        LinkProfile(rtt, jitter, loss),
                        {
                            "profile": str(profile_name),
                            "duration": float(profile_cfg.get("duration_ms", 0.0)),
                        },
                    )
                )
        return options

    ter_opts = _window_options(links.get("ter_uavnew", {}))
    uav_opts = _window_options(links.get("uavnew_sat", {}))
    sat_opts = [
        (LinkProfile(rtt, jitter, loss), {})
        for rtt, jitter, loss in itertools.product(
            _as_list(links.get("sat_ncc", {}).get("rtt_ms", 0.0)) or [0.0],
            _as_list(links.get("sat_ncc", {}).get("jitter_ms", 0.0)) or [0.0],
            _as_list(links.get("sat_ncc", {}).get("loss_pct", 0.0)) or [0.0],
        )
    ]

    def _profiles_match(ter_meta: Dict[str, Any], uav_meta: Dict[str, Any]) -> bool:
        ter_profile = ter_meta.get("profile")
        uav_profile = uav_meta.get("profile")
        if ter_profile is None and uav_profile is None:
            return True
        return ter_profile == uav_profile

    combos: List[ScenarioCombo] = []
    preferred_combos: List[ScenarioCombo] = []
    for ter_link, ter_meta in ter_opts:
        for uav_link, uav_meta in uav_opts:
            profile_ok = _profiles_match(ter_meta, uav_meta)
            rtt_ok = math.isclose(ter_link.rtt_ms, uav_link.rtt_ms, abs_tol=1e-6)
            for sat_link, sat_meta in sat_opts:
                metadata = {
                    "window_profile": f"{ter_meta.get('profile', 'default')}+{uav_meta.get('profile', 'default')}",
                    "window_duration_ms": max(ter_meta.get("duration", 0.0), uav_meta.get("duration", 0.0)),
                }
                window_links = metadata.setdefault(
                    "window_links",
                    {
                        "ter_uavnew": copy.deepcopy(links.get("ter_uavnew", {})),
                        "uavnew_sat": copy.deepcopy(links.get("uavnew_sat", {})),
                    },
                )
                window_links["ter_uavnew"]["selected_profile"] = ter_meta.get("profile", "default")
                window_links["uavnew_sat"]["selected_profile"] = uav_meta.get("profile", "default")
                metadata.update({k: v for k, v in sat_meta.items() if k not in metadata})
                combo = ScenarioCombo(ter_link, uav_link, sat_link, metadata)
                combos.append(combo)
                if profile_ok and rtt_ok:
                    preferred_combos.append(combo)

    if preferred_combos:
        return preferred_combos
    return combos


def _build_combos(config: Dict[str, Any]) -> List[ScenarioCombo]:
    scenario_kind = _scenario_type(config)
    links = config.get("links", {})
    if scenario_kind == "basic":
        return _basic_combos(links)
    if scenario_kind == "rain":
        return _rain_combos(links)
    if scenario_kind == "window":
        return _window_combos(links)
    return _basic_combos(links)


def run_ue_client(
    *,
    ue_container: str,
    context_container_path: Path,
    timeout_ms: int,
    pto: int,
) -> Dict[str, Any]:
    cmd = [
        "docker",
        "exec",
        ue_container,
        "python",
        "/app/app/ren2023_ue_client.py",
        "--context",
        str(context_container_path),
        "--timeout-ms",
        str(timeout_ms),
        "--pto",
        str(pto),
    ]
    try:
        result = run_command(cmd)
    except subprocess.CalledProcessError as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        emit_container_output("REN-UE", stdout, stderr)
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        for line in reversed(lines):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
        return {
            "status": "failed",
            "failed_stage": f"ue_client_exit_{exc.returncode}",
            "errno": exc.returncode,
            "attempts": 0,
            "timeout_ms": timeout_ms,
            "pto": pto,
            "latency_ms": 0.0,
            "bytes_online": 0.0,
            "msgs_online": 0,
        }
    emit_container_output("REN-UE", result.stdout, result.stderr)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("UE client produced no output")
    return json.loads(lines[-1])


def normalise_record(record: Dict[str, Any]) -> None:
    record.setdefault("failed_stage", "")
    record.setdefault("errno", 0)
    record.setdefault("attempts", 0)
    record.setdefault("cpu_ms_leo2", 0.0)
    record.setdefault("cpu_ms_ground", 0.0)
    record.setdefault("cpu_ms_ncc", record.get("cpu_ms_ground", 0.0))
    record.setdefault("processing_ms_leo2", 0.0)
    record.setdefault("bytes_online", 0.0)
    record.setdefault("msgs_online", 0)
    record.setdefault("latency_ms", 0.0)
    record.setdefault("ts5", "")
    record.setdefault("ts6", "")


def clear_all_netem(args: argparse.Namespace) -> None:
    clear_netem(args.ue_container, args.ue_interface)
    clear_netem(args.leo2_container, args.leo2_ue_interface)
    clear_netem(args.leo2_container, args.leo2_sat_interface)
    clear_netem(args.sat_container, args.sat_interface)
    clear_netem(args.sat_container, args.sat_ncc_interface)
    clear_netem(args.ncc_container, args.ncc_interface)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="REN2023 scenario runner")
    parser.add_argument("--config", type=Path, required=True, help="Scenario configuration file")
    parser.add_argument("--context", type=Path, default=DEFAULT_CONTEXT_HOST_PATH, help="Offline context path (host)")
    parser.add_argument(
        "--context-container",
        type=Path,
        default=DEFAULT_CONTEXT_CONTAINER_PATH,
        help="Offline context path inside containers",
    )
    parser.add_argument("--output", type=Path, required=True, help="CSV output path")
    parser.add_argument("--runs", type=int, default=None, help="Override runs per configuration")
    parser.add_argument("--ue-container", default="ren_ue", help="UE container name")
    parser.add_argument("--leo2-container", default="ren_leo2", help="LEO2 container name")
    parser.add_argument("--sat-container", default="ren_sat", help="SAT container name")
    parser.add_argument("--ncc-container", default="ren_ncc", help="NCC container name")
    parser.add_argument("--ue-interface", default="eth0")
    parser.add_argument("--leo2-ue-interface", default="eth0")
    parser.add_argument("--leo2-sat-interface", default="eth1")
    parser.add_argument("--sat-interface", default="eth0")
    parser.add_argument("--sat-ncc-interface", default="eth1")
    parser.add_argument("--ncc-interface", default="eth0")
    parser.add_argument("--rain-step-ms", type=int, default=100, help="Rain fade simulation step (unused placeholder)")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from an existing output CSV (skip completed runs)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = yaml.safe_load(args.config.read_text())
    ensure_context(args.context)

    scenario_kind = _scenario_type(config)
    combos = _build_combos(config)
    timeouts = config.get("timeouts_ms", [600])
    if not isinstance(timeouts, Sequence) or isinstance(timeouts, (str, bytes)):
        timeouts = [timeouts]
    pto_values = config.get("pto", [2])
    if not isinstance(pto_values, Sequence) or isinstance(pto_values, (str, bytes)):
        pto_values = [pto_values]
    runs = args.runs or config.get("runs", 5)

    preflight_missing: List[str] = []
    try:
        ensure_containers_running([args.ue_container, args.leo2_container, args.sat_container, args.ncc_container])
    except RuntimeError as exc:
        message = str(exc).strip()
        if message.lower().startswith("required docker containers are not running"):
            parts = message.split(":", 1)
            if len(parts) == 2 and parts[1].strip():
                preflight_missing = [name.strip() for name in parts[1].split(",")]
        else:
            raise

    args.output.parent.mkdir(parents=True, exist_ok=True)
    summary_cpu = defaultdict(float)
    success_count = 0
    total_runs = 0

    completed_keys = set()
    output_mode = "w"
    write_header = True
    if getattr(args, "resume", False) and args.output.exists():
        with args.output.open("r", encoding="utf-8", newline="") as existing_fh:
            reader = csv.DictReader(existing_fh)
            for row in reader:
                key = (
                    row.get("combo_index", ""),
                    row.get("timeout_ms", ""),
                    row.get("pto", ""),
                    row.get("run", ""),
                )
                completed_keys.add(key)
                total_runs += 1
                if row.get("status") == "ok":
                    success_count += 1
                try:
                    summary_cpu["ue"] += float(row.get("cpu_ms_ue") or 0.0)
                    summary_cpu["leo2"] += float(row.get("cpu_ms_leo2") or 0.0)
                    summary_cpu["ground"] += float(row.get("cpu_ms_ground") or 0.0)
                except ValueError:
                    # Ignore malformed numeric fields in existing rows
                    continue
        output_mode = "a"
        write_header = False

    with args.output.open(output_mode, encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        if write_header:
            writer.writeheader()

        for combo_index, combo in enumerate(combos):
            for timeout_ms in timeouts:
                for pto in pto_values:
                    for run_index in range(1, runs + 1):
                        if completed_keys:
                            key = (str(combo_index), str(timeout_ms), str(pto), str(run_index))
                            if key in completed_keys:
                                continue
                        base_record = {
                            "scenario": config.get("name", args.config.stem),
                            "mode": config.get("mode", "HANDOVER"),
                            "rtt_ms": f"{combo.ter_link.rtt_ms:.3f}/{combo.uav_link.rtt_ms:.3f}",
                            "loss_pct": "" if scenario_kind == "rain" else f"{combo.ter_link.loss_pct}/{combo.uav_link.loss_pct}",
                            "timeout_ms": str(timeout_ms),
                            "pto": str(pto),
                            "run": str(run_index),
                            "combo_index": str(combo_index),
                            "rain_profile": combo.metadata.get("rain_profile", ""),
                            "bw_factor": combo.metadata.get("bw_factor", ""),
                            "window_profile": combo.metadata.get("window_profile", ""),
                            "window_duration_ms": combo.metadata.get("window_duration_ms", ""),
                        }
                        attempt_counter = 0
                        while True:
                            attempt_counter += 1
                            record = base_record.copy()
                            failure_record: Dict[str, Any] | None = None
                            stage_note: Optional[str] = None
                            netem_set = False
                            rain_controllers: Dict[str, RainFadeController] = {}
                            window_controllers: Dict[str, WindowController] = {}
                            window_context: Dict[str, Any] = {}
                            rain_metrics_payload: Dict[str, float] = {}
                            window_metrics_payload: Dict[str, Any] = {}
                            try:
                                if preflight_missing:
                                    stage_note = f"netem_missing:{','.join(preflight_missing)}"
                                else:
                                    stage_note = _try_apply_netem(
                                        args.sat_container,
                                        args.sat_ncc_interface,
                                        combo.sat_link.rtt_ms,
                                        combo.sat_link.jitter_ms,
                                        combo.sat_link.loss_pct,
                                    )
                                    if stage_note is None:
                                        stage_note = _try_apply_netem(
                                            args.ncc_container,
                                            args.ncc_interface,
                                            combo.sat_link.rtt_ms,
                                            combo.sat_link.jitter_ms,
                                            combo.sat_link.loss_pct,
                                        )
                                    if stage_note is None:
                                        netem_set = True
                                        if scenario_kind == "rain":
                                            rain_controllers, stage_note = _start_rain_controllers(
                                                combo,
                                                combo_index,
                                                args,
                                                int(timeout_ms),
                                                int(pto),
                                                run_index,
                                                preflight_missing,
                                            )
                                            if stage_note is None and rain_controllers:
                                                netem_set = True
                                        elif scenario_kind == "window":
                                            window_controllers, stage_note = _start_window_controllers(
                                                combo,
                                                args,
                                                int(timeout_ms),
                                                int(pto),
                                                run_index,
                                                preflight_missing,
                                            )
                                            if stage_note is None:
                                                stage_note, window_context, window_metrics_payload, applied = _prepare_window_run(
                                                    combo,
                                                    args,
                                                    window_controllers,
                                                )
                                                if applied:
                                                    netem_set = True
                                        else:
                                            link_sequence = [
                                                (args.ue_container, args.ue_interface, combo.ter_link, None),
                                                (args.leo2_container, args.leo2_ue_interface, combo.ter_link, None),
                                                (args.leo2_container, args.leo2_sat_interface, combo.uav_link, None),
                                                (args.sat_container, args.sat_interface, combo.uav_link, None),
                                            ]
                                            for container, interface, profile, rate in link_sequence:
                                                stage_note = _try_apply_netem(
                                                    container,
                                                    interface,
                                                    profile.rtt_ms,
                                                    profile.jitter_ms,
                                                    profile.loss_pct,
                                                    rate_mbps=rate,
                                                )
                                                if stage_note is not None:
                                                    break
                                                netem_set = True
                                    result = None
                                    if stage_note is None:
                                        uplink_delay_ms = (
                                            int(window_context.get("uplink_delay_ms", 0)) if scenario_kind == "window" else 0
                                        )
                                        if uplink_delay_ms > 0:
                                            time.sleep(uplink_delay_ms / 1000.0)
                                        try:
                                            result = run_ue_client(
                                                ue_container=args.ue_container,
                                                context_container_path=args.context_container,
                                                timeout_ms=int(timeout_ms),
                                                pto=int(pto),
                                            )
                                        except KeyboardInterrupt:
                                            raise
                                        except RuntimeError as exc:
                                            failure_record = record.copy()
                                            failure_record.update(
                                                {
                                                    "status": "failed",
                                                    "failed_stage": f"ue_runtime:{exc}",
                                                    "errno": 0,
                                                    "latency_ms": 0.0,
                                                    "bytes_online": 0.0,
                                                    "msgs_online": 0,
                                                }
                                            )
                                        except Exception as exc:  # pragma: no cover - safeguard
                                            failure_record = record.copy()
                                            failure_record.update(
                                                {
                                                    "status": "failed",
                                                    "failed_stage": f"ue_error:{exc.__class__.__name__}",
                                                    "errno": 0,
                                                    "latency_ms": 0.0,
                                                    "bytes_online": 0.0,
                                                    "msgs_online": 0,
                                                }
                                            )
                                    if result is not None:
                                        record.update(result)
                            except Exception as exc:  # pragma: no cover - safeguard
                                if failure_record is None:
                                    failure_record = record.copy()
                                    failure_record.update(
                                        {
                                            "status": "failed",
                                            "failed_stage": f"orchestrator_error:{exc.__class__.__name__}",
                                            "errno": 0,
                                            "latency_ms": 0.0,
                                            "bytes_online": 0.0,
                                            "msgs_online": 0,
                                        }
                                    )
                            finally:
                                if rain_controllers:
                                    rain_metrics_payload = _collect_rain_metrics(rain_controllers.values())
                                    rain_errors: List[str] = []
                                    for link_name, ctrl in rain_controllers.items():
                                        try:
                                            ctrl.stop()
                                        except Exception:  # pragma: no cover
                                            continue
                                        fatal = ctrl.fatal_error()
                                        if fatal:
                                            rain_errors.append(f"{link_name}:{fatal}")
                                    if rain_errors and stage_note is None:
                                        stage_note = f"rain_controller_error:{';'.join(rain_errors)}"
                                    netem_set = True
                                if scenario_kind == "window" and window_controllers:
                                    durations: List[int] = []
                                    for link_ctx in window_context.get("links", {}).values():
                                        controller = link_ctx["controller"]
                                        controller.wait_for_close()
                                        for timer_obj in link_ctx.get("timers", []):
                                            timer_obj.cancel()
                                        if link_ctx.get("window_loss_active"):
                                            for pair in link_ctx.get("pairs", []):
                                                _try_apply_netem(
                                                    pair["container"],
                                                    pair["interface"],
                                                    pair["profile"].rtt_ms,
                                                    pair["jitter_ms"],
                                                    link_ctx["base_loss"],
                                                    rate_mbps=pair["rate"] if pair["rate"] else None,
                                                )
                                        metrics = controller.metrics()
                                        durations.append(metrics.last_window_ms)
                                        controller.shutdown()
                                    total_blackouts = window_context.get("total_blackouts", 0)
                                    window_metrics_payload.setdefault(
                                        "window_profile", combo.metadata.get("window_profile", "")
                                    )
                                    if durations:
                                        window_metrics_payload["window_duration_ms"] = min(durations)
                                    window_metrics_payload.setdefault(
                                        "uplink_delay_ms", window_context.get("uplink_delay_ms", 0)
                                    )
                                    window_metrics_payload.setdefault("scheduled_blackouts", total_blackouts)
                                    if "links" in window_context and "ter_uavnew" in window_context["links"]:
                                        window_metrics_payload.setdefault(
                                            "down_ready_ms", window_context["links"]["ter_uavnew"]["down_ready_ms"]
                                        )
                                        window_metrics_payload.setdefault(
                                            "guard_close_ms", window_context["links"]["ter_uavnew"]["guard_ms"]
                                        )
                                    netem_set = True
                                elif scenario_kind == "window":
                                    for ctrl in window_controllers.values():
                                        try:
                                            ctrl.shutdown()
                                        except Exception:  # pragma: no cover
                                            continue
                                if netem_set:
                                    clear_all_netem(args)

                            retry_stage: Optional[str] = None
                            if failure_record is None and _is_infra_stage(stage_note):
                                retry_stage = stage_note
                            elif failure_record is not None:
                                failed_stage = str(failure_record.get("failed_stage", ""))
                                if _is_infra_stage(failed_stage):
                                    retry_stage = failed_stage

                            if retry_stage and attempt_counter < MAX_INFRA_RETRIES:
                                print(
                                    f"[REN2023] Retrying combo {combo_index} run {run_index} due to {retry_stage} "
                                    f"(attempt {attempt_counter}/{MAX_INFRA_RETRIES})",
                                    flush=True,
                                )
                                continue
                            break

                        if rain_metrics_payload:
                            record.update(rain_metrics_payload)
                            if failure_record is not None:
                                failure_record.update(rain_metrics_payload)

                        if window_metrics_payload:
                            record.update(window_metrics_payload)
                            if failure_record is not None:
                                failure_record.update(window_metrics_payload)

                        if stage_note and failure_record is None:
                            failure_record = record.copy()
                            failure_record.update(
                                {
                                    "status": "failed",
                                    "failed_stage": stage_note,
                                    "errno": 0,
                                    "latency_ms": 0.0,
                                    "bytes_online": 0.0,
                                    "msgs_online": 0,
                                }
                            )

                        if failure_record is not None:
                            normalise_record(failure_record)
                            writer.writerow(failure_record)
                            total_runs += 1
                            continue

                        normalise_record(record)
                        writer.writerow(record)
                        total_runs += 1
                        if record.get("status") == "ok":
                            success_count += 1
                        summary_cpu["ue"] += float(record.get("cpu_ms_ue", 0.0))
                        summary_cpu["leo2"] += float(record.get("cpu_ms_leo2", 0.0))
                        summary_cpu["ground"] += float(record.get("cpu_ms_ground", 0.0))

    if total_runs == 0:
        success_rate = 0.0
    else:
        success_rate = success_count / total_runs
    summary = {
        "scenario": config.get("name", args.config.stem),
        "success_rate_online": success_rate,
        "cpu_ms_ue": summary_cpu["ue"] / max(1, total_runs),
        "cpu_ms_leo2": summary_cpu["leo2"] / max(1, total_runs),
        "cpu_ms_ground": summary_cpu["ground"] / max(1, total_runs),
        "cpu_ms_ncc": summary_cpu["ground"] / max(1, total_runs),
    }
    summary_path = args.output.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
