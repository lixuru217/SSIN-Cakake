#!/usr/bin/env python3

import os
import sys
from pathlib import Path

import pytest

PROTOCOLS_PATH = Path(__file__).resolve().parents[1] / "protocols"
if str(PROTOCOLS_PATH) not in sys.path:
    sys.path.insert(0, str(PROTOCOLS_PATH))

import ren2023  # type: ignore  # pylint: disable=import-error


def _provision_uav() -> tuple[ren2023.NCC, ren2023.UAV]:
    ncc = ren2023.NCC(domain="test-domain")
    uav = ren2023.UAV(identifier="UAV-1", puf=ren2023.PUFDevice.random())
    bundle = ncc.initiate_uav_registration(uav.identifier)
    response = uav.complete_registration(bundle)
    ncc.finalise_uav_registration(uav.identifier, response)
    return ncc, uav


def _provision_entities() -> tuple[ren2023.NCC, ren2023.UAV, ren2023.Terminal]:
    ncc = ren2023.NCC(domain="test-domain")

    uav = ren2023.UAV(identifier="UAV-1", puf=ren2023.PUFDevice.random())
    bundle_uav = ncc.initiate_uav_registration(uav.identifier)
    response_uav = uav.complete_registration(bundle_uav)
    ncc.finalise_uav_registration(uav.identifier, response_uav)

    ter = ren2023.Terminal(identifier="TER-1", puf=ren2023.PUFDevice.random())
    bundle_ter = ncc.initiate_terminal_registration(ter.identifier)
    response_ter = ter.complete_registration(bundle_ter)
    ncc.finalise_terminal_registration(ter.identifier, response_ter)

    return ncc, uav, ter


def _perform_phase1(ncc: ren2023.NCC, uav: ren2023.UAV) -> None:
    request = uav.start_auth_phase1()
    response, session_key = ncc.handle_uav_auth_request(request)
    assert isinstance(response, ren2023.NCCUAVAuthResponse)
    assert session_key is not None
    uav_response, uav_session, pid_used = uav.complete_auth_phase1(response)
    assert uav_session == session_key
    final_key = ncc.receive_uav_auth_response(pid_used, uav_response)
    assert final_key == session_key


def _perform_phase2(
    ncc: ren2023.NCC, uav: ren2023.UAV, ter: ren2023.Terminal
) -> tuple[bytes, bytes, str]:
    ter_request = ter.start_auth_phase2()
    uav_forward = uav.forward_terminal_request(ter_request)

    ncc_response, skt_n = ncc.handle_terminal_auth_request(uav_forward)
    assert isinstance(ncc_response, ren2023.NCCTerminalAuthResponse)
    assert skt_n is not None

    downlink = uav.process_terminal_auth_response(ter_request.pid, ncc_response)
    assert isinstance(downlink, ren2023.UAVToTerminalAuthForward)

    ter_response, ter_skt_n, ter_skt_u, pid_used, recovered_idu = ter.complete_auth_phase2(downlink)
    assert ter_skt_n == skt_n
    assert len(ter_skt_u) == ren2023.SESSION_KEY_SIZE

    forwarded = uav.forward_terminal_response(pid_used, ter_response)
    final_skt_n = ncc.receive_terminal_auth_response(pid_used, forwarded)
    assert final_skt_n == skt_n

    return skt_n, ter_skt_u, recovered_idu


def test_phase1_successful_handshake() -> None:
    ncc, uav = _provision_uav()

    request = uav.start_auth_phase1()
    ncc_response, ncc_session = ncc.handle_uav_auth_request(request)

    assert isinstance(ncc_response, ren2023.NCCUAVAuthResponse)
    assert ncc_session is not None

    uav_response, uav_session, pid_used = uav.complete_auth_phase1(ncc_response)
    assert uav_session == ncc_session

    final_session = ncc.receive_uav_auth_response(pid_used, uav_response)
    assert final_session == uav_session

    record = ncc.uav_records[uav.identifier]
    assert record.pid == uav.tuple1.pid
    assert record.challenge == uav.tuple1.challenge


def test_phase1_retry_from_invalid_pid() -> None:
    ncc, uav = _provision_uav()

    original_tuple1 = uav.tuple1
    assert original_tuple1 is not None

    # Simulate a desynchronised state by replacing the current tuple with an unknown PID.
    uav.tuple1 = ren2023.TupleEntry(
        os.urandom(ren2023.PID_SIZE).hex(),
        os.urandom(ren2023.CHALLENGE_SIZE),
    )

    request = uav.start_auth_phase1()
    ncc_response, ncc_session = ncc.handle_uav_auth_request(request)

    assert isinstance(ncc_response, ren2023.NCCUAVIdentityInvalidResponse)
    assert ncc_session is None
    assert uav.handle_invalid_identity(ncc_response) is True

    # Roll tuple1 back to the known-good entry and retry with Tuple0 as described in the phase.
    uav.tuple1 = ren2023.TupleEntry(original_tuple1.pid, original_tuple1.challenge)

    retry_request = uav.start_auth_phase1(use_backup_tuple=True)
    retry_response, retry_session = ncc.handle_uav_auth_request(retry_request)

    assert isinstance(retry_response, ren2023.NCCUAVAuthResponse)
    assert retry_session is not None

    uav_retry_message, uav_retry_session, pid_used = uav.complete_auth_phase1(retry_response)
    assert uav_retry_session == retry_session

    final_session = ncc.receive_uav_auth_response(pid_used, uav_retry_message)
    assert final_session == retry_session


def test_phase2_successful_handshake() -> None:
    ncc, uav, ter = _provision_entities()
    _perform_phase1(ncc, uav)

    skt_n, skt_u, recovered_idu = _perform_phase2(ncc, uav, ter)
    assert recovered_idu == uav.identifier
    assert len(skt_u) == ren2023.SESSION_KEY_SIZE

    record = ncc.terminal_records[ter.identifier]
    assert record.pid == ter.tuple1.pid
    assert record.challenge == ter.tuple1.challenge


def test_phase2_retry_from_invalid_pid() -> None:
    ncc, uav, ter = _provision_entities()
    _perform_phase1(ncc, uav)

    original_tuple1 = ter.tuple1
    assert original_tuple1 is not None

    ter.tuple1 = ren2023.TupleEntry(
        os.urandom(ren2023.PID_SIZE).hex(),
        os.urandom(ren2023.CHALLENGE_SIZE),
    )

    ter_request = ter.start_auth_phase2()
    uav_forward = uav.forward_terminal_request(ter_request)

    ncc_response, skt_n = ncc.handle_terminal_auth_request(uav_forward)
    assert isinstance(ncc_response, ren2023.NCCTerminalIdentityInvalidResponse)
    assert skt_n is None

    downlink = uav.process_terminal_auth_response(ter_request.pid, ncc_response)
    assert isinstance(downlink, ren2023.NCCTerminalIdentityInvalidResponse)
    assert ter.handle_terminal_invalid_response(downlink) is True

    # Restore tuple1 so that tuple0 (holding the previous valid entry) can be used as backup.
    ter.tuple1 = original_tuple1

    retry_request = ter.start_auth_phase2(use_backup_tuple=True)
    retry_forward = uav.forward_terminal_request(retry_request)

    retry_response, retry_skt_n = ncc.handle_terminal_auth_request(retry_forward)
    assert isinstance(retry_response, ren2023.NCCTerminalAuthResponse)
    assert retry_skt_n is not None

    retry_downlink = uav.process_terminal_auth_response(retry_request.pid, retry_response)
    assert isinstance(retry_downlink, ren2023.UAVToTerminalAuthForward)

    retry_payload, ter_skt_n, _, pid_used, _ = ter.complete_auth_phase2(retry_downlink)
    assert ter_skt_n == retry_skt_n

    forwarded = uav.forward_terminal_response(pid_used, retry_payload)
    final_skt_n = ncc.receive_terminal_auth_response(pid_used, forwarded)
    assert final_skt_n == retry_skt_n


def _provision_second_uav(ncc: ren2023.NCC, identifier: str) -> ren2023.UAV:
    new_uav = ren2023.UAV(identifier=identifier, puf=ren2023.PUFDevice.random())
    bundle = ncc.initiate_uav_registration(new_uav.identifier)
    response = new_uav.complete_registration(bundle)
    ncc.finalise_uav_registration(new_uav.identifier, response)
    _perform_phase1(ncc, new_uav)
    return new_uav


def test_phase3_handover_success() -> None:
    ncc, uav_old, ter = _provision_entities()
    _perform_phase1(ncc, uav_old)
    _perform_phase2(ncc, uav_old, ter)

    uav_new = _provision_second_uav(ncc, "UAV-2")

    ho_request = ter.start_handover()
    uplink = uav_new.receive_handover_request(ho_request)

    ncc_response = ncc.handle_handover_request(uplink)
    assert isinstance(ncc_response, ren2023.NCCUAVHOResponse)

    downlink = uav_new.process_handover_response(ho_request.pid, ncc_response)
    assert isinstance(downlink, ren2023.UAVTerHOResponse)

    ter_response, skt_nu, pid_new, idnu = ter.complete_handover(downlink)
    assert idnu == uav_new.identifier
    assert len(skt_nu) == ren2023.SESSION_KEY_SIZE

    final_key = uav_new.finalise_handover(ho_request.pid, ter_response)
    assert final_key == skt_nu

    ncc.mark_handover_complete(ho_request.pid)

    record = ncc.terminal_records[ter.identifier]
    assert record.pid == pid_new
    assert ter.tuple1.pid == pid_new


def test_phase3_retry_from_invalid_pid() -> None:
    ncc, uav_old, ter = _provision_entities()
    _perform_phase1(ncc, uav_old)
    _perform_phase2(ncc, uav_old, ter)

    original_tuple1 = ter.tuple1
    assert original_tuple1 is not None

    uav_new = _provision_second_uav(ncc, "UAV-3")

    ter.tuple1 = ren2023.TupleEntry(
        os.urandom(ren2023.PID_SIZE).hex(),
        original_tuple1.challenge,
    )

    ho_request = ter.start_handover()
    uplink = uav_new.receive_handover_request(ho_request)

    ncc_response = ncc.handle_handover_request(uplink)
    assert isinstance(ncc_response, ren2023.NCCTerminalIdentityInvalidResponse)

    invalid_forward = uav_new.process_handover_response(ho_request.pid, ncc_response)
    assert isinstance(invalid_forward, ren2023.NCCTerminalIdentityInvalidResponse)
    assert ter.handle_handover_invalid_response(invalid_forward) is True

    ter.tuple1 = original_tuple1

    retry_request = ter.start_handover(use_backup_tuple=True)
    retry_uplink = uav_new.receive_handover_request(retry_request)

    retry_response = ncc.handle_handover_request(retry_uplink)
    assert isinstance(retry_response, ren2023.NCCUAVHOResponse)

    retry_downlink = uav_new.process_handover_response(retry_request.pid, retry_response)
    assert isinstance(retry_downlink, ren2023.UAVTerHOResponse)

    retry_payload, skt_nu, pid_new, idnu = ter.complete_handover(retry_downlink)
    assert idnu == uav_new.identifier

    final_key = uav_new.finalise_handover(retry_request.pid, retry_payload)
    assert final_key == skt_nu

    record = ncc.terminal_records[ter.identifier]
    assert record.pid == pid_new

    ncc.mark_handover_complete(retry_request.pid)


def test_ncc_cancel_handover_reverts_state() -> None:
    ncc, uav_old, ter = _provision_entities()
    _perform_phase1(ncc, uav_old)
    _perform_phase2(ncc, uav_old, ter)

    uav_new = _provision_second_uav(ncc, "UAV-4")

    original_record = ncc.terminal_records[ter.identifier]

    ho_request = ter.start_handover()
    uplink = uav_new.receive_handover_request(ho_request)
    ncc_response = ncc.handle_handover_request(uplink)
    assert isinstance(ncc_response, ren2023.NCCUAVHOResponse)

    ncc.cancel_handover(ho_request.pid)

    restored = ncc.terminal_records[ter.identifier]
    assert restored.pid == original_record.pid
    assert ho_request.pid in ncc._terminal_pid_index  # type: ignore[attr-defined]
    assert ho_request.pid not in ncc._pending_handover_sessions  # type: ignore[attr-defined]


def test_terminal_mac_mismatch_aborts() -> None:
    ncc, uav, ter = _provision_entities()
    _perform_phase1(ncc, uav)

    ter_request = ter.start_auth_phase2()
    uav_forward = uav.forward_terminal_request(ter_request)
    ncc_response, _ = ncc.handle_terminal_auth_request(uav_forward)
    assert isinstance(ncc_response, ren2023.NCCTerminalAuthResponse)

    downlink = uav.process_terminal_auth_response(ter_request.pid, ncc_response)
    assert isinstance(downlink, ren2023.UAVToTerminalAuthForward)

    tampered = ren2023.UAVToTerminalAuthForward(
        downlink.pid_masked,
        downlink.nn,
        downlink.nu,
        downlink.cid_u,
        os.urandom(len(downlink.authn_t)),
    )

    with pytest.raises(ValueError):
        ter.complete_auth_phase2(tampered)


def test_uav_auth_mac_mismatch_aborts() -> None:
    ncc, uav = _provision_uav()

    request = uav.start_auth_phase1()
    response, _ = ncc.handle_uav_auth_request(request)
    assert isinstance(response, ren2023.NCCUAVAuthResponse)

    tampered = ren2023.NCCUAVAuthResponse(
        response.pid_masked,
        response.nn,
        os.urandom(len(response.authn_u)),
    )

    with pytest.raises(ValueError):
        uav.complete_auth_phase1(tampered)
