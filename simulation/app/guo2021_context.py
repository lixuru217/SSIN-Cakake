#!/usr/bin/env python3
"""Helpers to build and load Guo2021 offline contexts for the simulators."""

from __future__ import annotations

import copy
import pickle
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable

from guo2021 import (
    NCCState,
    SatelliteState,
    GroundStationState,
    SessionIdentifier,
    UserDeviceState,
    run_access_handshake,
)


@dataclass
class GuoUERecord:
    state: UserDeviceState
    password: str
    biometric: bytes
    session_id: SessionIdentifier


@dataclass
class GuoOfflineContext:
    ncc: NCCState
    satellites: Dict[str, SatelliteState]
    ground: GroundStationState
    ue_records: Dict[str, GuoUERecord]
    old_satellite_id: str
    new_satellite_id: str
    ground_id: str


def generate_offline_context(
    ue_ids: Iterable[str],
    *,
    old_satellite_id: str = "L-01",
    new_satellite_id: str = "L-02",
    ground_id: str = "GS-01",
) -> GuoOfflineContext:
    ncc = NCCState()
    old_sat = ncc.register_satellite(old_satellite_id)
    new_sat = ncc.register_satellite(new_satellite_id)
    ground = ncc.register_ground_station(ground_id)

    ue_records: Dict[str, GuoUERecord] = {}
    base_ts = int(time.time())

    for idx, ue_id in enumerate(ue_ids):
        password = f"{ue_id}-pw"
        biometric = f"bio-{ue_id}".encode("utf-8")
        ue_state = ncc.register_user(ue_id, password=password, biometric=biometric)

        # Establish an initial session between UE, old satellite, and ground.
        ts_seed = base_ts + (idx * 10)
        run_access_handshake(
            ue_state,
            old_sat,
            ground,
            T1=ts_seed,
            tolerance_sat=600,
            tolerance_gs_inner=600,
            tolerance_gs_outer=1200,
            tolerance_user=600,
        )
        if not ue_state.sessions:
            raise RuntimeError("failed to establish initial session for UE")
        session_id = next(iter(ue_state.sessions.keys()))

        ue_records[ue_id] = GuoUERecord(
            state=ue_state,
            password=password,
            biometric=biometric,
            session_id=session_id,
        )

    satellites = {
        old_satellite_id: old_sat,
        new_satellite_id: new_sat,
    }

    return GuoOfflineContext(
        ncc=ncc,
        satellites=satellites,
        ground=ground,
        ue_records=ue_records,
        old_satellite_id=old_satellite_id,
        new_satellite_id=new_satellite_id,
        ground_id=ground_id,
    )


def save_context(context: GuoOfflineContext, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        pickle.dump(context, fh)


def load_context(path: Path) -> GuoOfflineContext:
    with path.open("rb") as fh:
        context = pickle.load(fh)
    if not isinstance(context, GuoOfflineContext):
        raise TypeError("offline file does not contain GuoOfflineContext")
    return context


def get_ue_state(context: GuoOfflineContext, ue_id: str) -> UserDeviceState:
    if ue_id not in context.ue_records:
        raise KeyError(f"unknown UE id {ue_id}")
    return copy.deepcopy(context.ue_records[ue_id].state)


def get_ue_credentials(context: GuoOfflineContext, ue_id: str) -> tuple[str, bytes]:
    if ue_id not in context.ue_records:
        raise KeyError(f"unknown UE id {ue_id}")
    record = context.ue_records[ue_id]
    return record.password, record.biometric


def get_ue_session_id(context: GuoOfflineContext, ue_id: str) -> SessionIdentifier:
    if ue_id not in context.ue_records:
        raise KeyError(f"unknown UE id {ue_id}")
    return context.ue_records[ue_id].session_id


def get_satellite_state(context: GuoOfflineContext, satellite_id: str) -> SatelliteState:
    if satellite_id not in context.satellites:
        raise KeyError(f"unknown satellite id {satellite_id}")
    return copy.deepcopy(context.satellites[satellite_id])


def get_old_satellite_state(context: GuoOfflineContext) -> SatelliteState:
    return get_satellite_state(context, context.old_satellite_id)


def get_new_satellite_state(context: GuoOfflineContext) -> SatelliteState:
    return get_satellite_state(context, context.new_satellite_id)


def get_ground_state(context: GuoOfflineContext) -> GroundStationState:
    return copy.deepcopy(context.ground)


def get_identifiers(context: GuoOfflineContext) -> tuple[str, str, str]:
    return context.old_satellite_id, context.new_satellite_id, context.ground_id
