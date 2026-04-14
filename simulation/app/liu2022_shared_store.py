#!/usr/bin/env python3
"""Shared state helpers for Liu2022 simulators."""

from __future__ import annotations

import fcntl
import pickle
from pathlib import Path
from typing import Dict, Optional


class BlindFactorStore:
    """Persist NCC blind factors to a shared file so AP containers stay in sync."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _load_locked(self, fh) -> Dict[int, bytes]:
        fh.seek(0)
        try:
            return pickle.load(fh)
        except EOFError:
            return {}

    def snapshot(self) -> Dict[int, bytes]:
        if not self._path.exists():
            return {}
        with self._path.open("rb") as fh:
            fcntl.flock(fh, fcntl.LOCK_SH)
            try:
                return self._load_locked(fh)
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def read(self, index: int) -> Optional[bytes]:
        data = self.snapshot()
        return data.get(index)

    def write(self, index: int, value: bytes) -> None:
        mode = "r+b" if self._path.exists() else "w+b"
        with self._path.open(mode) as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                data = self._load_locked(fh)
                if data.get(index) == value:
                    return
                data[index] = value
                fh.seek(0)
                pickle.dump(data, fh)
                fh.truncate()
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)
