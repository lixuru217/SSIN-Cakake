#!/usr/bin/env python3
"""Utilities for REN2023 offline context generation and loading."""

from __future__ import annotations

import copy
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Tuple

PROTOCOLS_PATH = Path(__file__).resolve().parents[2] / "protocols"
import sys

if str(PROTOCOLS_PATH) not in sys.path:
    sys.path.insert(0, str(PROTOCOLS_PATH))

import ren2023


@dataclass
class Ren2023OfflineContext:
    """Snapshot of REN2023 entity state after initial access authentication."""

    ncc: ren2023.NCC
    uav_old: ren2023.UAV
    uav_new: ren2023.UAV
    terminal: ren2023.Terminal
    domain: str
    handover_cache: dict[str, tuple[ren2023.UAVTerHOResponse, ren2023._StoredHandoverPayload]] = field(default_factory=dict)  # type: ignore[attr-defined]


def _instantiate_entities(
    *,
    domain: str,
    terminal_id: str,
    uav_old_id: str,
    uav_new_id: str,
) -> Tuple[ren2023.NCC, ren2023.UAV, ren2023.UAV, ren2023.Terminal]:
    ncc = ren2023.NCC(domain=domain)

    def _make_uav(identifier: str) -> ren2023.UAV:
        return ren2023.UAV(identifier=identifier, puf=ren2023.PUFDevice.random())

    uav_old = _make_uav(uav_old_id)
    uav_new = _make_uav(uav_new_id)
    terminal = ren2023.Terminal(identifier=terminal_id, puf=ren2023.PUFDevice.random())

    return ncc, uav_old, uav_new, terminal


def _register_uav(ncc: ren2023.NCC, uav: ren2023.UAV) -> None:
    bundle = ncc.initiate_uav_registration(uav.identifier)
    response = uav.complete_registration(bundle)
    ncc.finalise_uav_registration(uav.identifier, response)

    request = uav.start_auth_phase1()
    reply, session_key = ncc.handle_uav_auth_request(request)
    if session_key is None:
        raise RuntimeError("UAV authentication rejected during provisioning")
    uav_response, _, pid_used = uav.complete_auth_phase1(reply)
    ncc.receive_uav_auth_response(pid_used, uav_response)


def _register_terminal(
    ncc: ren2023.NCC,
    terminal: ren2023.Terminal,
    serving_uav: ren2023.UAV,
) -> None:
    bundle = ncc.initiate_terminal_registration(terminal.identifier)
    response = terminal.complete_registration(bundle)
    ncc.finalise_terminal_registration(terminal.identifier, response)

    request = terminal.start_auth_phase2()
    uplink = serving_uav.forward_terminal_request(request)
    reply, session_key = ncc.handle_terminal_auth_request(uplink)
    if session_key is None:
        raise RuntimeError("Terminal authentication rejected during provisioning")
    downlink = serving_uav.process_terminal_auth_response(request.pid, reply)
    ue_payload, _, _, pid_used, _ = terminal.complete_auth_phase2(downlink)
    forward = serving_uav.forward_terminal_response(pid_used, ue_payload)
    ncc.receive_terminal_auth_response(pid_used, forward)


def generate_offline_context(
    *,
    domain: str = "ren2023.sim",
    terminal_id: str = "TER-01",
    uav_old_id: str = "LEO-01",
    uav_new_id: str = "LEO-02",
) -> Ren2023OfflineContext:
    """Create a fresh REN2023 environment ready for handover testing."""
    ncc, uav_old, uav_new, terminal = _instantiate_entities(
        domain=domain,
        terminal_id=terminal_id,
        uav_old_id=uav_old_id,
        uav_new_id=uav_new_id,
    )

    _register_uav(ncc, uav_old)
    _register_uav(ncc, uav_new)
    _register_terminal(ncc, terminal, uav_old)

    return Ren2023OfflineContext(
        ncc=ncc,
        uav_old=uav_old,
        uav_new=uav_new,
        terminal=terminal,
        domain=domain,
    )


def save_context(context: Ren2023OfflineContext, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        pickle.dump(context, fh)


def load_context(path: Path) -> Ren2023OfflineContext:
    with path.open("rb") as fh:
        stored: Ren2023OfflineContext = pickle.load(fh)
    # Deep copy to ensure each caller operates on independent state.
    cache = getattr(stored, "handover_cache", {})
    return Ren2023OfflineContext(
        ncc=copy.deepcopy(stored.ncc),
        uav_old=copy.deepcopy(stored.uav_old),
        uav_new=copy.deepcopy(stored.uav_new),
        terminal=copy.deepcopy(stored.terminal),
        domain=stored.domain,
        handover_cache=copy.deepcopy(cache),
    )
