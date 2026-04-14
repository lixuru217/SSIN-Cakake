#!/usr/bin/env python3
"""Helpers to capture process CPU usage for REN2023 simulations."""

from __future__ import annotations

import os
import resource
from contextlib import contextmanager
from typing import Callable, Generator, Iterable, Tuple, TypeVar

T = TypeVar("T")


class CpuCollector:
    """Minimal collector that samples /proc/self/stat around critical sections."""

    _TICKS_PER_SECOND = os.sysconf(os.sysconf_names["SC_CLK_TCK"])

    def sample_ms(self) -> float:
        """Return the current process CPU usage in milliseconds."""
        try:
            with open("/proc/self/stat", "r", encoding="utf-8") as fh:
                fields = fh.read().split()
            utime = int(fields[13])
            stime = int(fields[14])
            total_ticks = utime + stime
            return total_ticks * 1000.0 / self._TICKS_PER_SECOND
        except (FileNotFoundError, PermissionError, IndexError, ValueError):
            usage = resource.getrusage(resource.RUSAGE_SELF)
            return (float(usage.ru_utime) + float(usage.ru_stime)) * 1000.0

    def measure(self, func: Callable[..., T], *args, **kwargs) -> Tuple[float, T]:
        """Execute func and return (cpu_ms, result)."""
        before = self.sample_ms()
        result = func(*args, **kwargs)
        after = self.sample_ms()
        return max(0.0, after - before), result

    @contextmanager
    def scoped(self) -> Generator[Callable[[], float], None, None]:
        """Context manager yielding a closure that returns the CPU delta on demand."""
        before = self.sample_ms()

        def finish() -> float:
            after = self.sample_ms()
            return max(0.0, after - before)

        yield finish


DEFAULT_CPU_COLLECTOR = CpuCollector()
