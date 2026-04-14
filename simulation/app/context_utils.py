#!/usr/bin/env python3
"""Helpers to load the offline SSINAuth context for the simulators."""

from __future__ import annotations

import copy
import pickle
from pathlib import Path
from typing import Optional, Tuple

from ssinauth import OfflineContext, SBPreAuthCache, UEOfflineRecord, UEPreAuthCache


def load_offline_context(path: Path) -> OfflineContext:
    with path.open("rb") as fh:
        context = pickle.load(fh)
    if not isinstance(context, OfflineContext):
        raise TypeError("offline context file does not contain OfflineContext")
    return context


def get_ue_state(context: OfflineContext, ue_id: str) -> UEOfflineRecord:
    if ue_id not in context.ue_records:
        raise KeyError(f"unknown UE id {ue_id}")
    return copy.deepcopy(context.ue_records[ue_id])


def get_authenticator_state(context: OfflineContext) -> Tuple:
    authenticator = copy.deepcopy(context.authenticator)
    incoming = copy.deepcopy(context.authenticator.incoming_sessions)
    return authenticator, incoming


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_ue_cache(cache_dir: Path, ue_id: str, cache: UEPreAuthCache) -> Path:
    _ensure_dir(cache_dir)
    path = cache_dir / f"ue-{ue_id}.pkl"
    with path.open("wb") as fh:
        pickle.dump(cache, fh)
    return path


def write_sb_cache(cache_dir: Path, ue_id: str, cache: SBPreAuthCache) -> Path:
    _ensure_dir(cache_dir)
    path = cache_dir / f"sb-{ue_id}.pkl"
    with path.open("wb") as fh:
        pickle.dump(cache, fh)
    return path


def load_ue_cache(cache_dir: Path, ue_id: str) -> Optional[UEPreAuthCache]:
    path = cache_dir / f"ue-{ue_id}.pkl"
    if not path.exists():
        return None
    with path.open("rb") as fh:
        cache = pickle.load(fh)
    if not isinstance(cache, UEPreAuthCache):
        raise TypeError(f"{path} does not contain UEPreAuthCache")
    return cache


def load_sb_cache(cache_dir: Path, ue_id: str) -> Optional[SBPreAuthCache]:
    path = cache_dir / f"sb-{ue_id}.pkl"
    if not path.exists():
        return None
    with path.open("rb") as fh:
        cache = pickle.load(fh)
    if not isinstance(cache, SBPreAuthCache):
        raise TypeError(f"{path} does not contain SBPreAuthCache")
    return cache
