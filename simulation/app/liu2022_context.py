#!/usr/bin/env python3
"""Helpers to build and load Liu2022 offline contexts for the simulators."""

from __future__ import annotations

import copy
import pickle
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional

from liu2022 import APState, GMState, NCCState, UEState, GroupCredential


@dataclass
class LiuUERecord:
    state: UEState


@dataclass
class LiuOfflineContext:
    ncc: NCCState
    gm: GMState
    aps: Dict[str, APState]
    ue_records: Dict[str, LiuUERecord]


def generate_offline_context(
    ue_ids: Iterable[str],
    *,
    ap_ids: Iterable[str] = ("AP-01", "AP-02"),
    gm_id: str = "GM-01",
) -> LiuOfflineContext:
    ncc = NCCState()
    gm = ncc.register_gm(gm_id)
    aps: Dict[str, APState] = {}
    for ap_id in ap_ids:
        aps[ap_id] = ncc.register_ap(ap_id)

    ue_records: Dict[str, LiuUERecord] = {}
    for ue_id in ue_ids:
        ue_state = ncc.register_ue(ue_id)
        ue_records[ue_id] = LiuUERecord(state=ue_state)

    base_ts = int(time.time() * 1000)
    for idx, ap in enumerate(aps.values()):
        ts1 = base_ts + (idx * 25)
        request = ap.start_group_request(ts1)
        response = gm.process_group_request(request, now=ts1 + 5)
        ap.process_group_response(response, now=ts1 + 10)

    if len(aps) > 1:
        for ap_id, ap_state in aps.items():
            for assignment in ap_state.assignments.values():
                hac_entries = []
                for record in gm.ap_groups.values():
                    if record.apgid == assignment.apgid:
                        continue
                    hac_entries.append(
                        GroupCredential(
                            target_apgid=record.apgid,
                            sgk_bytes=record.sgk_bytes,
                            expiry_ts=record.expiry_ts,
                        )
                    )
                assignment.hac = hac_entries

    return LiuOfflineContext(
        ncc=ncc,
        gm=gm,
        aps=aps,
        ue_records=ue_records,
    )


def save_context(context: LiuOfflineContext, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        pickle.dump(context, fh)


def load_context(path: Path) -> LiuOfflineContext:
    with path.open("rb") as fh:
        context = pickle.load(fh)
    if not isinstance(context, LiuOfflineContext):
        raise TypeError("offline file does not contain LiuOfflineContext")
    return context


def get_gm_state(context: LiuOfflineContext) -> GMState:
    return copy.deepcopy(context.gm)


def get_ap_state(context: LiuOfflineContext, ap_id: str) -> APState:
    if ap_id not in context.aps:
        raise KeyError(f"unknown AP id {ap_id}")
    return copy.deepcopy(context.aps[ap_id])


def get_ue_state(context: LiuOfflineContext, ue_id: str) -> UEState:
    if ue_id not in context.ue_records:
        raise KeyError(f"unknown UE id {ue_id}")
    return copy.deepcopy(context.ue_records[ue_id].state)


def _runtime_path(cache_dir: Path, ue_id: str) -> Path:
    return cache_dir / f"liu-runtime-{ue_id}.pkl"


def save_ue_runtime(cache_dir: Path, ue_id: str, state: UEState) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = _runtime_path(cache_dir, ue_id)
    with path.open("wb") as fh:
        pickle.dump(state, fh)


def load_ue_runtime(cache_dir: Path, ue_id: str) -> Optional[UEState]:
    path = _runtime_path(cache_dir, ue_id)
    if not path.exists():
        return None
    with path.open("rb") as fh:
        state = pickle.load(fh)
    if not isinstance(state, UEState):
        raise TypeError(f"{path} does not contain UEState")
    return state
