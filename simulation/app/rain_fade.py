#!/usr/bin/env python3
"""Helpers to model rain-fade dynamics with Gilbert–Elliott bursts and bandwidth throttling."""

from __future__ import annotations

import logging
import random
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple


logger = logging.getLogger("rain_fade")

@dataclass
class RainFadeMetrics:
    bad_ticks: int
    total_ticks: int
    bad_ratio: float
    last_state: str
    blackout_ticks: int
    blackout_events: int
    blackout_active: bool


class RainFadeController:
    """Run a Gilbert–Elliott process and update netem parameters on the UE↔LEO2 link."""

    def __init__(
        self,
        *,
        apply_netem: Callable[..., None],
        ue_container: str,
        ue_interface: str,
        leo2_container: str,
        leo2_interface: str,
        base_rtt_ms: float,
        base_jitter_ms: float,
        loss_good_pct: float,
        loss_bad_pct: float,
        p_gb: float,
        p_bg: float,
        step_ms: int,
        down_rate_mbps: float,
        up_rate_mbps: Optional[float],
        bw_factor: float,
        bad_jitter_extra_ms: float = 0.0,
        queue_limit: Optional[int] = 1000,
        downlink_only: bool = False,
        seed: Optional[int] = None,
        micro_blackout: Optional[Dict[str, float]] = None,
        extra_endpoints: Optional[Iterable[Tuple[str, str, Optional[float]]]] = None,
    ) -> None:
        self._apply_netem = apply_netem
        self._ue_container = ue_container
        self._ue_interface = ue_interface
        self._leo2_container = leo2_container
        self._leo2_interface = leo2_interface
        self._base_rtt_ms = base_rtt_ms
        self._base_jitter_ms = base_jitter_ms
        self._loss_good_pct = loss_good_pct
        self._loss_bad_pct = loss_bad_pct
        self._p_gb = p_gb
        self._p_bg = p_bg
        self._step_ms = max(step_ms, 1)
        self._down_rate_mbps = down_rate_mbps
        self._up_rate_mbps = up_rate_mbps if not downlink_only else None
        self._bw_factor = bw_factor
        self._bad_jitter_extra_ms = bad_jitter_extra_ms
        self._queue_limit = queue_limit
        self._rng = random.Random(seed)
        stationary_den = self._p_gb + self._p_bg
        if stationary_den > 0:
            bad_probability = self._p_gb / stationary_den
            self._state = "bad" if self._rng.random() < bad_probability else "good"
        else:
            self._state = "good"
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._bad_ticks = 0
        self._total_ticks = 0
        self._micro_prob_per_tick = 0.0
        self._blackout_ticks_length = 0
        self._blackout_ticks_remaining = 0
        self._blackout_loss_pct = 100.0
        self._blackout_ticks_total = 0
        self._blackout_events = 0
        self._consecutive_errors = 0
        self._max_error_attempts = 5
        self._last_error: Optional[str] = None
        self._fatal_error: Optional[str] = None
        self._netem_targets: List[Tuple[str, str, Optional[float]]] = [
            (self._ue_container, self._ue_interface, self._up_rate_mbps),
            (self._leo2_container, self._leo2_interface, self._down_rate_mbps),
        ]
        if extra_endpoints:
            for container, interface, rate in extra_endpoints:
                target = (container, interface, rate)
                if target not in self._netem_targets:
                    self._netem_targets.append(target)
        if micro_blackout:
            duration_ms = float(micro_blackout.get("duration_ms", 0.0))
            if duration_ms > 0:
                probability_per_s = float(micro_blackout.get("probability_per_s", 0.0))
                self._micro_prob_per_tick = max(0.0, probability_per_s) * (self._step_ms / 1000.0)
                self._blackout_ticks_length = max(1, int(round(duration_ms / self._step_ms)))
                self._blackout_loss_pct = float(micro_blackout.get("loss_pct", 100.0))

    def start(self) -> None:
        with self._lock:
            self._apply_state_locked(False)
        self._thread = threading.Thread(target=self._run_loop, name="RainFadeController", daemon=True)
        self._stop_event.clear()
        self._consecutive_errors = 0
        self._last_error = None
        self._fatal_error = None
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join()
        self._thread = None

    def metrics(self) -> RainFadeMetrics:
        with self._lock:
            ratio = (self._bad_ticks / self._total_ticks) if self._total_ticks else 0.0
            return RainFadeMetrics(
                bad_ticks=self._bad_ticks,
                total_ticks=self._total_ticks,
                bad_ratio=ratio,
                last_state=self._state,
                blackout_ticks=self._blackout_ticks_total,
                blackout_events=self._blackout_events,
                blackout_active=self._blackout_ticks_remaining > 0,
            )

    def snapshot(self) -> Dict[str, float]:
        metrics = self.metrics()
        return {
            "bad_ticks": metrics.bad_ticks,
            "total_ticks": metrics.total_ticks,
            "bad_ratio": metrics.bad_ratio,
            "last_state": metrics.last_state,
            "bw_factor": self._bw_factor,
            "down_rate_mbps": self._down_rate_mbps,
            "up_rate_mbps": self._up_rate_mbps or 0.0,
            "blackout_ticks": metrics.blackout_ticks,
            "blackout_events": metrics.blackout_events,
            "blackout_active": metrics.blackout_active,
        }

    def fatal_error(self) -> Optional[str]:
        return self._fatal_error

    def _run_loop(self) -> None:
        step_seconds = self._step_ms / 1000.0
        while not self._stop_event.wait(step_seconds):
            with self._lock:
                self._total_ticks += 1
                blackout_active = False
                if self._blackout_ticks_remaining > 0:
                    self._blackout_ticks_remaining -= 1
                    self._blackout_ticks_total += 1
                    blackout_active = True
                elif self._micro_prob_per_tick > 0.0 and self._rng.random() < self._micro_prob_per_tick:
                    self._blackout_ticks_remaining = self._blackout_ticks_length - 1
                    self._blackout_events += 1
                    self._blackout_ticks_total += 1
                    blackout_active = True

                if self._state == "bad":
                    self._bad_ticks += 1
                    if self._rng.random() < self._p_bg:
                        self._state = "good"
                else:
                    if self._rng.random() < self._p_gb:
                        self._state = "bad"
                self._apply_state_locked(blackout_active)

    def _apply_state_locked(self, blackout_active: bool) -> None:
        jitter = self._base_jitter_ms
        loss_pct = self._loss_good_pct
        if self._state == "bad":
            jitter += self._bad_jitter_extra_ms
            loss_pct = self._loss_bad_pct
        if blackout_active:
            loss_pct = max(loss_pct, self._blackout_loss_pct)
        try:
            for container, interface, rate in self._netem_targets:
                self._apply_netem(
                    container,
                    interface,
                    self._base_rtt_ms,
                    jitter,
                    loss_pct,
                    rate_mbps=rate,
                    limit_packets=self._queue_limit,
                )
            self._consecutive_errors = 0
            self._last_error = None
        except Exception as exc:  # pylint: disable=broad-except
            formatted = _format_netem_error(exc)
            self._last_error = formatted
            self._consecutive_errors += 1
            if self._consecutive_errors >= self._max_error_attempts:
                self._fatal_error = formatted
                logger.error(
                    "rain-fade controller failed to apply netem (fatal after %d attempts): %s",
                    self._consecutive_errors,
                    formatted,
                )
                self._stop_event.set()
            else:
                logger.warning(
                    "rain-fade controller hit transient netem error (%d/%d): %s",
                    self._consecutive_errors,
                    self._max_error_attempts,
                    formatted,
                )
                time.sleep(min(0.5, self._step_ms / 1000.0))


def _format_netem_error(exc: Exception) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        details = stderr or stdout
        if details:
            return f"{exc}; details={details}"
    return str(exc)
