#!/usr/bin/env python3
"""Utility helpers for CPU and wall-clock measurements."""

from __future__ import annotations

import os
import resource
import time
from dataclasses import dataclass


_TICKS_PER_SECOND = os.sysconf(os.sysconf_names["SC_CLK_TCK"])


@dataclass
class CpuSample:
    user_ticks: int
    sys_ticks: int
    user_secs: float
    sys_secs: float

    @property
    def total_ticks(self) -> int:
        return self.user_ticks + self.sys_ticks

    def to_ms(self) -> float:
        return (self.user_secs + self.sys_secs) * 1000.0


def sample_cpu() -> CpuSample:
    """Read the current process CPU usage from /proc/self/stat."""
    usage = resource.getrusage(resource.RUSAGE_SELF)
    try:
        with open("/proc/self/stat", "r", encoding="utf-8") as fh:
            fields = fh.read().split()
        user_ticks = int(fields[13])
        sys_ticks = int(fields[14])
    except (FileNotFoundError, PermissionError, IndexError, ValueError):
        user_ticks = int(usage.ru_utime * _TICKS_PER_SECOND)
        sys_ticks = int(usage.ru_stime * _TICKS_PER_SECOND)

    return CpuSample(
        user_ticks=user_ticks,
        sys_ticks=sys_ticks,
        user_secs=float(usage.ru_utime),
        sys_secs=float(usage.ru_stime),
    )


@dataclass
class Timer:
    start_time: float

    @classmethod
    def start(cls) -> "Timer":
        return cls(start_time=time.monotonic())

    def stop_ms(self) -> float:
        return (time.monotonic() - self.start_time) * 1000.0
