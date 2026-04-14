#!/usr/bin/env python3
"""Offline context helpers for the Yang2024 vehicular handover simulator."""

from __future__ import annotations

import copy
import pickle
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Tuple

PROTOCOLS_PATH = Path(__file__).resolve().parents[2] / "protocols"
if str(PROTOCOLS_PATH) not in sys.path:
    sys.path.insert(0, str(PROTOCOLS_PATH))

import yang2024


DEFAULT_VALIDITY_TS = 10_000_000_000_000  # ~317 years in milliseconds, effectively non-expiring for tests


@dataclass
class VehicleRecord:
    real_identity: str
    pseudo_identity: yang2024.PseudoIdentity
    partial_secret: yang2024.PartialSecretKey
    secret_key: yang2024.VehicleSecretKey
    public_key: yang2024.VehiclePublicKey


@dataclass
class YangOfflineContext:
    parameters: yang2024.PublicParameters
    vehicle_records: Dict[str, VehicleRecord]
    rsu_ids: Tuple[str, str]
    app_id: str


def _clone_vehicle(record: VehicleRecord, parameters: yang2024.PublicParameters) -> yang2024.VehicleState:
    state = yang2024.VehicleState(record.real_identity, parameters)
    state.pseudo_identity = copy.deepcopy(record.pseudo_identity)
    state.partial_secret = copy.deepcopy(record.partial_secret)
    state.secret_key = copy.deepcopy(record.secret_key)
    state.public_key = copy.deepcopy(record.public_key)
    return state


def generate_offline_context(
    vehicle_ids: Iterable[str],
    *,
    rsu_ids: Tuple[str, str] = ("RSU-01", "RSU-02"),
    app_id: str = "APP-01",
    validity_ts: int = DEFAULT_VALIDITY_TS,
) -> YangOfflineContext:
    ta = yang2024.TrustedAuthority()
    parameters = ta.public_parameters()

    vehicle_records: Dict[str, VehicleRecord] = {}

    for vehicle_id in vehicle_ids:
        vehicle = yang2024.VehicleState(vehicle_id, parameters)
        request = vehicle.create_pseudo_id_request(validity_ts)
        response = ta.issue_pseudo_identity(request)
        vehicle.receive_pseudo_identity(response)
        partial = ta.issue_partial_secret(vehicle.pseudo_identity)
        vehicle.install_partial_secret(partial)

        vehicle_records[vehicle_id] = VehicleRecord(
            real_identity=vehicle_id,
            pseudo_identity=copy.deepcopy(vehicle.pseudo_identity),
            partial_secret=copy.deepcopy(vehicle.partial_secret),
            secret_key=copy.deepcopy(vehicle.secret_key),
            public_key=copy.deepcopy(vehicle.public_key),
        )

    return YangOfflineContext(
        parameters=parameters,
        vehicle_records=vehicle_records,
        rsu_ids=rsu_ids,
        app_id=app_id,
    )


def save_context(context: YangOfflineContext, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        pickle.dump(context, fh)


def load_context(path: Path) -> YangOfflineContext:
    with path.open("rb") as fh:
        context = pickle.load(fh)
    if not isinstance(context, YangOfflineContext):
        raise TypeError("offline file did not contain YangOfflineContext")
    return context


def get_vehicle_state(context: YangOfflineContext, vehicle_id: str) -> yang2024.VehicleState:
    if vehicle_id not in context.vehicle_records:
        raise KeyError(f"unknown vehicle id {vehicle_id}")
    return _clone_vehicle(context.vehicle_records[vehicle_id], context.parameters)


def get_rsu_ids(context: YangOfflineContext) -> Tuple[str, str]:
    return tuple(context.rsu_ids)


def get_parameters(context: YangOfflineContext) -> yang2024.PublicParameters:
    return copy.deepcopy(context.parameters)


__all__ = [
    "DEFAULT_VALIDITY_TS",
    "VehicleRecord",
    "YangOfflineContext",
    "generate_offline_context",
    "save_context",
    "load_context",
    "get_vehicle_state",
    "get_rsu_ids",
    "get_parameters",
]
