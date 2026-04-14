#!/usr/bin/env python3
"""Helpers to simulate short visibility windows by toggling UE↔LEO2 connectivity."""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Optional


IPTABLES_PATH = "/usr/sbin/iptables"

logger = logging.getLogger("window_controller")


def _is_container_running(container: str) -> bool:
    cmd = ["docker", "inspect", "-f", "{{.State.Running}}", container]
    result = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        logger.warning("failed to inspect container %s: %s", container, result.stderr.strip())
        return False
    return result.stdout.strip().lower() == "true"


def _run_iptables(container: str, args: list[str], action: str, *, log_on_error: bool = True) -> subprocess.CompletedProcess:
    cmd = ["docker", "exec", container, IPTABLES_PATH] + args
    result = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0 and log_on_error:
        logger.warning(
            "iptables %s failed on %s (%s): %s",
            action,
            container,
            " ".join(args),
            result.stderr.strip(),
        )
    return result


def _ensure_drop_rule(container: str, chain: str, direction_flag: str, interface: str, present: bool) -> None:
    if not _is_container_running(container):
        logger.warning("container %s not running; skip iptables update", container)
        return

    check_args = ["-C", chain, direction_flag, interface, "-j", "DROP"]
    result = _run_iptables(container, check_args, "check", log_on_error=False)
    if present:
        if result.returncode != 0:
            _run_iptables(container, ["-I", chain, "1", direction_flag, interface, "-j", "DROP"], "add")
    else:
        if result.returncode != 0:
            return
        while result.returncode == 0:
            delete_result = _run_iptables(container, ["-D", chain, direction_flag, interface, "-j", "DROP"], "delete")
            if delete_result.returncode != 0:
                break
            result = _run_iptables(container, check_args, "check", log_on_error=False)


@dataclass
class WindowMetrics:
    is_open: bool
    last_window_ms: int
    total_open_ms: int


class WindowController:
    """Gate bidirectional visibility between two containers by toggling iptables DROP rules."""

    def __init__(
        self,
        *,
        container_a: Optional[str] = None,
        interface_a: Optional[str] = None,
        container_b: Optional[str] = None,
        interface_b: Optional[str] = None,
        ue_container: Optional[str] = None,
        ue_interface: Optional[str] = None,
        leo2_container: Optional[str] = None,
        leo2_interface: Optional[str] = None,
    ) -> None:
        resolved_container_a = container_a if container_a is not None else ue_container
        resolved_interface_a = interface_a if interface_a is not None else ue_interface
        resolved_container_b = container_b if container_b is not None else leo2_container
        resolved_interface_b = interface_b if interface_b is not None else leo2_interface

        missing = [
            name
            for name, value in [
                ("container_a", resolved_container_a),
                ("interface_a", resolved_interface_a),
                ("container_b", resolved_container_b),
                ("interface_b", resolved_interface_b),
            ]
            if value is None
        ]
        if missing:
            raise ValueError(f"WindowController missing arguments: {', '.join(missing)}")

        self._container_a = resolved_container_a
        self._interface_a = resolved_interface_a
        self._container_b = resolved_container_b
        self._interface_b = resolved_interface_b
        self._lock = threading.Lock()
        self._state = False
        self._current_timer: Optional[threading.Timer] = None
        self._open_start: Optional[float] = None
        self._last_window_ms = 0
        self._total_open_ms = 0
        self._apply_drop(False)

    def open_for(self, duration_s: float) -> threading.Timer:
        with self._lock:
            self._set_state(True)
            timer = threading.Timer(duration_s, self.close)
            self._current_timer = timer
            timer.start()
            return timer

    def close(self) -> None:
        with self._lock:
            self._set_state(False)

    def wait_for_close(self) -> None:
        timer = None
        with self._lock:
            timer = self._current_timer
        if timer:
            timer.join()

    def ensure_open(self) -> None:
        with self._lock:
            self._set_state(True)

    def metrics(self) -> WindowMetrics:
        with self._lock:
            return WindowMetrics(
                is_open=self._state,
                last_window_ms=self._last_window_ms,
                total_open_ms=self._total_open_ms,
            )

    def shutdown(self) -> None:
        with self._lock:
            if self._current_timer and self._current_timer.is_alive():
                self._current_timer.cancel()
            self._current_timer = None
            self._set_state(False)
        self._apply_drop(False)
        with self._lock:
            self._state = False
            self._open_start = None

    def _set_state(self, open_state: bool) -> None:
        if self._state == open_state:
            return
        if open_state:
            self._apply_drop(False)
            self._open_start = time.perf_counter()
        else:
            if self._open_start is not None:
                elapsed_ms = int(round((time.perf_counter() - self._open_start) * 1000))
                self._last_window_ms = elapsed_ms
                self._total_open_ms += elapsed_ms
                self._open_start = None
            self._apply_drop(True)
        self._state = open_state

    def _apply_drop(self, present: bool) -> None:
        # Apply to both directions on the linked containers.
        rules = [
            (self._container_a, "INPUT", "-i", self._interface_a),
            (self._container_b, "INPUT", "-i", self._interface_b),
        ]
        for container, chain, flag, iface in rules:
            _ensure_drop_rule(container, chain, flag, iface, present)

    def drop_downlink_for(self, duration_ms: int) -> None:
        if duration_ms <= 0:
            return
        with self._lock:
            if not self._state:
                return
            _ensure_drop_rule(self._container_a, "INPUT", "-i", self._interface_a, True)

        def restore() -> None:
            with self._lock:
                if not self._state:
                    return
                _ensure_drop_rule(self._container_a, "INPUT", "-i", self._interface_a, False)

        threading.Timer(duration_ms / 1000.0, restore).start()

    def inject_blackout(self, duration_ms: int) -> None:
        if duration_ms <= 0:
            return
        with self._lock:
            if not self._state:
                return
            self._apply_drop(True)

        def restore() -> None:
            with self._lock:
                if not self._state:
                    return
                self._apply_drop(False)

        threading.Timer(duration_ms / 1000.0, restore).start()
