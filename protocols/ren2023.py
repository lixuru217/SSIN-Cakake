#!/usr/bin/env python3
"""
Reference implementation of the Ren et al. (2023) SIN authentication protocol.

The code keeps the message flow close to the specification so the simulation
harness can reuse it alongside the other protocol variants.  Every intermediate
value is represented explicitly which lets the unit tests exercise error paths
such as MAC verification failures and tuple rollbacks.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

PID_SIZE = 16
CHALLENGE_SIZE = 32
NONCE_SIZE = 16
SESSION_KEY_SIZE = 32
IDENTITY_SIZE = 32


def _encode_length(data: bytes) -> bytes:
    return len(data).to_bytes(2, "big") + data


def hash_bytes(label: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(label)
    for part in parts:
        digest.update(_encode_length(part))
    return digest.digest()


def expand_mask(label: bytes, length: int, *parts: bytes) -> bytes:
    buf = bytearray()
    counter = 0
    while len(buf) < length:
        counter_bytes = counter.to_bytes(4, "big")
        buf.extend(hash_bytes(label + counter_bytes, *parts))
        counter += 1
    return bytes(buf[:length])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def random_bytes(length: int) -> bytes:
    return os.urandom(length)


def random_pid() -> str:
    return random_bytes(PID_SIZE).hex()


def pid_to_bytes(pid: str) -> bytes:
    data = bytes.fromhex(pid)
    if len(data) != PID_SIZE:
        raise ValueError("invalid PID length")
    return data


def pid_from_bytes(data: bytes) -> str:
    if len(data) != PID_SIZE:
        raise ValueError("invalid PID length")
    return data.hex()


def identity_bytes(identifier: str) -> bytes:
    return hash_bytes(b"ren2023/id", identifier.encode("utf-8"))


def derive_uav_session_key(nu: bytes, nn: bytes, challenge: bytes, response: bytes) -> bytes:
    return hash_bytes(b"ren2023/uav/sk", nu, nn, challenge, response)


def derive_terminal_sk_tn(nt: bytes, nn: bytes, challenge: bytes, response: bytes) -> bytes:
    return hash_bytes(b"ren2023/terminal/sk_tn", nt, nn, challenge, response)


def derive_terminal_sk_tu(nt: bytes, nu: bytes, sk_tn: bytes) -> bytes:
    return hash_bytes(b"ren2023/terminal/sk_tu", nt, nu, sk_tn)


def derive_sk_tnu(id_u_bytes: bytes, nu: bytes, sk_tn: bytes) -> bytes:
    return hash_bytes(b"ren2023/handover/sk_tnu", id_u_bytes, nu, sk_tn)


def update_challenge(id_bytes: bytes, challenge: bytes, response: bytes) -> bytes:
    return hash_bytes(b"ren2023/challenge/update", id_bytes, challenge, response)[:CHALLENGE_SIZE]


def mask_pid_uav(id_bytes: bytes, pid_bytes: bytes, session_key: bytes) -> bytes:
    return expand_mask(b"ren2023/uav/pidmask", PID_SIZE, id_bytes, pid_bytes, session_key)


def mask_response_uav(id_bytes: bytes, nn: bytes, response: bytes) -> bytes:
    return expand_mask(b"ren2023/uav/rmask", len(response), id_bytes, nn, response)


def mask_pid_terminal(id_bytes: bytes, pid_bytes: bytes, sk_tn: bytes) -> bytes:
    return expand_mask(b"ren2023/terminal/pidmask", PID_SIZE, id_bytes, pid_bytes, sk_tn)


def mask_response_terminal(id_bytes: bytes, nn: bytes, response: bytes) -> bytes:
    return expand_mask(b"ren2023/terminal/rmask", len(response), id_bytes, nn, response)


def mask_cid_u(pid_bytes: bytes, sk_tu: bytes, length: int) -> bytes:
    return expand_mask(b"ren2023/cid_u", length, pid_bytes, sk_tu)


def mask_cid_handover(pid_bytes: bytes, sk_tnu: bytes, length: int) -> bytes:
    return expand_mask(b"ren2023/handover/cid", length, pid_bytes, sk_tnu)


def mask_response_handover(id_bytes: bytes, nu: bytes, response: bytes) -> bytes:
    return expand_mask(b"ren2023/handover/rmask", len(response), id_bytes, nu, response)


def auth_n_to_u(
    pid_bytes: bytes,
    id_bytes: bytes,
    nu: bytes,
    nn: bytes,
    pid_masked: bytes,
    challenge: bytes,
    session_key: bytes,
) -> bytes:
    return hash_bytes(
        b"ren2023/uav/auth_n_to_u",
        pid_bytes,
        id_bytes,
        nu,
        nn,
        pid_masked,
        challenge,
        session_key,
    )


def auth_u_to_n(pid_new_bytes: bytes, challenge_new: bytes, r_masked: bytes, session_key: bytes) -> bytes:
    return hash_bytes(
        b"ren2023/uav/auth_u_to_n",
        pid_new_bytes,
        challenge_new,
        r_masked,
        session_key,
    )


def auth_n_to_terminal(
    pid_bytes: bytes,
    id_t_bytes: bytes,
    id_u_bytes: bytes,
    nt: bytes,
    nu: bytes,
    nn: bytes,
    pid_masked: bytes,
    challenge: bytes,
    sk_tn: bytes,
) -> bytes:
    return hash_bytes(
        b"ren2023/terminal/auth_n_to_t",
        pid_bytes,
        id_t_bytes,
        id_u_bytes,
        nt,
        nu,
        nn,
        pid_masked,
        challenge,
        sk_tn,
    )


def auth_terminal_to_n(
    pid_new_bytes: bytes,
    nt: bytes,
    nn: bytes,
    challenge_new: bytes,
    r_masked: bytes,
    sk_tn: bytes,
) -> bytes:
    return hash_bytes(
        b"ren2023/terminal/auth_t_to_n",
        pid_new_bytes,
        nt,
        nn,
        challenge_new,
        r_masked,
        sk_tn,
    )


def auth_terminal_to_u(
    r_masked: bytes,
    auth_tn: bytes,
    id_u_bytes: bytes,
    nu: bytes,
    sk_tu: bytes,
) -> bytes:
    return hash_bytes(
        b"ren2023/terminal/auth_t_to_u",
        r_masked,
        auth_tn,
        id_u_bytes,
        nu,
        sk_tu,
    )


def auth_handover_n_to_t(
    pid_bytes: bytes,
    id_u_bytes: bytes,
    nu: bytes,
    pid_masked: bytes,
    sk_tnu: bytes,
) -> bytes:
    return hash_bytes(
        b"ren2023/handover/auth_n_to_t",
        pid_bytes,
        id_u_bytes,
        nu,
        pid_masked,
        sk_tnu,
    )


def auth_handover_t_to_u(
    id_u_bytes: bytes,
    pid_bytes: bytes,
    nu: bytes,
    n_t: bytes,
    sk_tnu: bytes,
) -> bytes:
    return hash_bytes(
        b"ren2023/handover/auth_t_to_u",
        id_u_bytes,
        pid_bytes,
        nu,
        n_t,
        sk_tnu,
    )


################################################################################
# Registration tuples and payloads
################################################################################


@dataclass(frozen=True)
class TupleEntry:
    pid: str
    challenge: bytes


@dataclass(frozen=True)
class RegistrationBundle:
    pid: str
    challenge: bytes
    public_key: bytes


@dataclass(frozen=True)
class RegistrationResponse:
    pid: str
    challenge: bytes
    response: bytes


################################################################################
# Message payload representations
################################################################################


@dataclass(frozen=True)
class UAVAuthRequest:
    pid: str
    nu: bytes


@dataclass(frozen=True)
class NCCUAVAuthResponse:
    pid_masked: bytes
    nn: bytes
    authn_u: bytes


@dataclass(frozen=True)
class NCCUAVIdentityInvalidResponse:
    pid: str
    nu: bytes
    signature: bytes


@dataclass(frozen=True)
class UAVAuthResponse:
    r_masked: bytes
    auth_un: bytes


@dataclass(frozen=True)
class TerminalAuthRequest:
    pid: str
    nt: bytes


@dataclass(frozen=True)
class UAVForwardedTerminalRequest:
    pid: str
    nt: bytes
    nu: bytes
    uav_id: str


@dataclass(frozen=True)
class NCCTerminalAuthResponse:
    pid_masked: bytes
    nn: bytes
    authn_t: bytes
    sk_tu: bytes


@dataclass(frozen=True)
class NCCTerminalIdentityInvalidResponse:
    pid: str
    nt: bytes
    signature: bytes


@dataclass(frozen=True)
class UAVToTerminalAuthForward:
    pid_masked: bytes
    nn: bytes
    nu: bytes
    cid_u: bytes
    authn_t: bytes


@dataclass(frozen=True)
class TerminalAuthResponse:
    r_masked: bytes
    auth_tn: bytes
    auth_tu: bytes


@dataclass(frozen=True)
class UAVForwardedTerminalResponse:
    r_masked: bytes
    auth_tn: bytes


@dataclass(frozen=True)
class TerminalHandoverRequest:
    pid: str


@dataclass(frozen=True)
class UAVHandoverUplink:
    pid: str
    nu: bytes
    uav_id: str


@dataclass(frozen=True)
class NCCUAVHOResponse:
    cid_nu: bytes
    pid_masked: bytes
    sk_tnu: bytes
    auth_nu_t: bytes


@dataclass(frozen=True)
class NCCUAVHOIdentityInvalidResponse:
    pid: str
    signature: bytes


@dataclass(frozen=True)
class UAVTerHOResponse:
    nu: bytes
    cid_nu: bytes
    pid_masked: bytes
    sk_tnu: bytes
    auth_nu_t: bytes


@dataclass(frozen=True)
class TerminalHandoverResponse:
    n_t: bytes
    auth_tnu: bytes
    r_masked: bytes


################################################################################
# PUF abstraction
################################################################################


class PUFDevice:
    """Simple deterministic PUF simulator backed by a per-device secret."""

    def __init__(self, secret: bytes):
        if not secret:
            raise ValueError("PUF secret must not be empty")
        self._secret = secret

    def evaluate(self, challenge: bytes) -> bytes:
        return hmac.new(self._secret, challenge, hashlib.sha256).digest()

    @classmethod
    def random(cls) -> "PUFDevice":
        return cls(os.urandom(32))


################################################################################
# NCC state and pending-session tracking
################################################################################


@dataclass
class _UAVRecord:
    identifier: str
    id_bytes: bytes
    pid: str
    challenge: bytes
    response: bytes
    backup_pid: Optional[str] = None
    backup_challenge: Optional[bytes] = None
    backup_response: Optional[bytes] = None


@dataclass
class _TerminalRecord:
    identifier: str
    id_bytes: bytes
    pid: str
    challenge: bytes
    response: bytes
    serving_uav: Optional[str] = None
    sk_tn: Optional[bytes] = None
    backup_pid: Optional[str] = None
    backup_challenge: Optional[bytes] = None
    backup_response: Optional[bytes] = None


@dataclass
class _PendingUAVSession:
    identifier: str
    id_bytes: bytes
    old_pid: str
    new_pid: str
    challenge_old: bytes
    response_old: bytes
    challenge_new: bytes
    session_key: bytes
    nn: bytes


@dataclass
class _PendingTerminalSession:
    terminal_id: str
    id_t_bytes: bytes
    uav_id: str
    id_u_bytes: bytes
    old_pid: str
    new_pid: str
    challenge_old: bytes
    response_old: bytes
    challenge_new: bytes
    nt: bytes
    nn: bytes
    nu: bytes
    sk_tn: bytes
    sk_tu: bytes


@dataclass
class _PendingHandoverSession:
    terminal_id: str
    id_t_bytes: bytes
    uav_id: str
    id_u_bytes: bytes
    old_pid: str
    new_pid: str
    challenge_old: bytes
    response_old: bytes
    challenge_new: bytes
    nu: bytes
    sk_tn: bytes
    sk_tnu: bytes


@dataclass
class _StoredHandoverPayload:
    terminal_id: str
    uav_id: str
    pid_new: str
    challenge_new: bytes
    response_new: bytes
    sk_tnu: bytes


_HANDOVER_INBOX: Dict[str, _StoredHandoverPayload] = {}


class NCC:
    """Network control centre coordinating registrations and authentications."""

    def __init__(self, domain: str):
        self.domain = domain
        self.public_key = os.urandom(IDENTITY_SIZE)
        self._sign_key = os.urandom(IDENTITY_SIZE)
        self.uav_records: Dict[str, _UAVRecord] = {}
        self.terminal_records: Dict[str, _TerminalRecord] = {}
        self._uav_pid_index: Dict[str, Tuple[str, str]] = {}
        self._terminal_pid_index: Dict[str, Tuple[str, str]] = {}
        self._pending_uav_sessions: Dict[str, _PendingUAVSession] = {}
        self._pending_terminal_sessions: Dict[str, _PendingTerminalSession] = {}
        self._pending_handover_sessions: Dict[str, _PendingHandoverSession] = {}

    # ---------------------------------------------------------------- registration

    def initiate_uav_registration(self, identifier: str) -> RegistrationBundle:
        pid = random_pid()
        challenge = random_bytes(CHALLENGE_SIZE)
        return RegistrationBundle(pid, challenge, self.public_key)

    def finalise_uav_registration(self, identifier: str, response: RegistrationResponse) -> None:
        record = _UAVRecord(
            identifier=identifier,
            id_bytes=identity_bytes(identifier),
            pid=response.pid,
            challenge=response.challenge,
            response=response.response,
        )
        self.uav_records[identifier] = record
        self._uav_pid_index[response.pid] = (identifier, "current")

    def initiate_terminal_registration(self, identifier: str) -> RegistrationBundle:
        pid = random_pid()
        challenge = random_bytes(CHALLENGE_SIZE)
        return RegistrationBundle(pid, challenge, self.public_key)

    def finalise_terminal_registration(self, identifier: str, response: RegistrationResponse) -> None:
        record = _TerminalRecord(
            identifier=identifier,
            id_bytes=identity_bytes(identifier),
            pid=response.pid,
            challenge=response.challenge,
            response=response.response,
        )
        self.terminal_records[identifier] = record
        self._terminal_pid_index[response.pid] = (identifier, "current")

    def _promote_uav_backup(self, record: _UAVRecord) -> None:
        if record.backup_pid is None or record.backup_challenge is None or record.backup_response is None:
            raise ValueError("no UAV backup tuple available")
        current_pid = record.pid
        current_challenge = record.challenge
        current_response = record.response
        record.pid = record.backup_pid
        record.challenge = record.backup_challenge
        record.response = record.backup_response
        record.backup_pid = current_pid
        record.backup_challenge = current_challenge
        record.backup_response = current_response
        if current_pid is not None:
            self._uav_pid_index[current_pid] = (record.identifier, "backup")
        self._uav_pid_index[record.pid] = (record.identifier, "current")

    def _promote_terminal_backup(self, record: _TerminalRecord) -> None:
        if record.backup_pid is None or record.backup_challenge is None or record.backup_response is None:
            raise ValueError("no terminal backup tuple available")
        current_pid = record.pid
        current_challenge = record.challenge
        current_response = record.response
        record.pid = record.backup_pid
        record.challenge = record.backup_challenge
        record.response = record.backup_response
        record.backup_pid = current_pid
        record.backup_challenge = current_challenge
        record.backup_response = current_response
        if current_pid is not None:
            self._terminal_pid_index[current_pid] = (record.identifier, "backup")
        self._terminal_pid_index[record.pid] = (record.identifier, "current")

    def _commit_uav_tuple(self, record: _UAVRecord, new_pid: str, challenge_new: bytes, response_new: bytes) -> None:
        if record.backup_pid is not None:
            self._uav_pid_index.pop(record.backup_pid, None)
        if record.pid is not None:
            self._uav_pid_index.pop(record.pid, None)
        record.backup_pid = record.pid
        record.backup_challenge = record.challenge
        record.backup_response = record.response
        if record.backup_pid is not None:
            self._uav_pid_index[record.backup_pid] = (record.identifier, "backup")
        record.pid = new_pid
        record.challenge = challenge_new
        record.response = response_new
        self._uav_pid_index[new_pid] = (record.identifier, "current")

    def _commit_terminal_tuple(
        self,
        record: _TerminalRecord,
        new_pid: str,
        challenge_new: bytes,
        response_new: bytes,
    ) -> None:
        if record.backup_pid is not None:
            self._terminal_pid_index.pop(record.backup_pid, None)
        if record.pid is not None:
            self._terminal_pid_index.pop(record.pid, None)
        record.backup_pid = record.pid
        record.backup_challenge = record.challenge
        record.backup_response = record.response
        if record.backup_pid is not None:
            self._terminal_pid_index[record.backup_pid] = (record.identifier, "backup")
        record.pid = new_pid
        record.challenge = challenge_new
        record.response = response_new
        self._terminal_pid_index[new_pid] = (record.identifier, "current")

    # ---------------------------------------------------------------- UAV access

    def handle_uav_auth_request(self, request: UAVAuthRequest) -> Tuple[object, Optional[bytes]]:
        index_entry = self._uav_pid_index.get(request.pid)
        if index_entry is None:
            signature = hash_bytes(
                b"ren2023/uav/invalid",
                self.public_key,
                request.pid.encode("utf-8"),
                request.nu,
            )
            return NCCUAVIdentityInvalidResponse(request.pid, request.nu, signature), None
        identifier, slot = index_entry
        record = self.uav_records[identifier]
        if slot == "backup":
            self._promote_uav_backup(record)
        nn = random_bytes(NONCE_SIZE)
        session_key = derive_uav_session_key(request.nu, nn, record.challenge, record.response)
        new_pid = random_pid()
        pid_mask = mask_pid_uav(record.id_bytes, pid_to_bytes(record.pid), session_key)
        pid_masked = xor_bytes(pid_to_bytes(new_pid), pid_mask)
        authn_u = auth_n_to_u(
            pid_to_bytes(record.pid),
            record.id_bytes,
            request.nu,
            nn,
            pid_masked,
            record.challenge,
            session_key,
        )
        challenge_new = update_challenge(record.id_bytes, record.challenge, record.response)

        pending = _PendingUAVSession(
            identifier=record.identifier,
            id_bytes=record.id_bytes,
            old_pid=record.pid,
            new_pid=new_pid,
            challenge_old=record.challenge,
            response_old=record.response,
            challenge_new=challenge_new,
            session_key=session_key,
            nn=nn,
        )
        self._pending_uav_sessions[record.pid] = pending

        return NCCUAVAuthResponse(pid_masked, nn, authn_u), session_key

    def receive_uav_auth_response(self, pid_used: str, response: UAVAuthResponse) -> bytes:
        pending = self._pending_uav_sessions.get(pid_used)
        if pending is None:
            raise ValueError("no pending UAV session for PID")

        expected = auth_u_to_n(
            pid_to_bytes(pending.new_pid),
            pending.challenge_new,
            response.r_masked,
            pending.session_key,
        )
        if response.auth_un != expected:
            raise ValueError("UAV authentication tag mismatch")

        mask = mask_response_uav(pending.id_bytes, pending.nn, pending.response_old)
        r_new = xor_bytes(response.r_masked, mask)

        record = self.uav_records[pending.identifier]
        self._commit_uav_tuple(record, pending.new_pid, pending.challenge_new, r_new)

        del self._pending_uav_sessions[pid_used]
        return pending.session_key

    # ---------------------------------------------------------------- terminal access

    def handle_terminal_auth_request(self, request: UAVForwardedTerminalRequest) -> Tuple[object, Optional[bytes]]:
        index_entry = self._terminal_pid_index.get(request.pid)
        if index_entry is None:
            signature = hash_bytes(
                b"ren2023/terminal/invalid",
                self.public_key,
                request.pid.encode("utf-8"),
                request.nt,
            )
            return NCCTerminalIdentityInvalidResponse(request.pid, request.nt, signature), None

        if request.uav_id not in self.uav_records:
            raise ValueError("unknown UAV identifier")

        identifier, slot = index_entry
        record = self.terminal_records[identifier]
        if slot == "backup":
            self._promote_terminal_backup(record)
        uav_record = self.uav_records[request.uav_id]

        nn = random_bytes(NONCE_SIZE)
        sk_tn = derive_terminal_sk_tn(request.nt, nn, record.challenge, record.response)
        sk_tu = derive_terminal_sk_tu(request.nt, request.nu, sk_tn)
        new_pid = random_pid()
        pid_mask = mask_pid_terminal(record.id_bytes, pid_to_bytes(record.pid), sk_tn)
        pid_masked = xor_bytes(pid_to_bytes(new_pid), pid_mask)
        challenge_new = update_challenge(record.id_bytes, record.challenge, record.response)
        authn_t = auth_n_to_terminal(
            pid_to_bytes(record.pid),
            record.id_bytes,
            uav_record.id_bytes,
            request.nt,
            request.nu,
            nn,
            pid_masked,
            record.challenge,
            sk_tn,
        )

        pending = _PendingTerminalSession(
            terminal_id=record.identifier,
            id_t_bytes=record.id_bytes,
            uav_id=uav_record.identifier,
            id_u_bytes=uav_record.id_bytes,
            old_pid=record.pid,
            new_pid=new_pid,
            challenge_old=record.challenge,
            response_old=record.response,
            challenge_new=challenge_new,
            nt=request.nt,
            nn=nn,
            nu=request.nu,
            sk_tn=sk_tn,
            sk_tu=sk_tu,
        )
        self._pending_terminal_sessions[record.pid] = pending

        response = NCCTerminalAuthResponse(pid_masked, nn, authn_t, sk_tu)
        return response, sk_tn

    def receive_terminal_auth_response(self, pid_used: str, response: UAVForwardedTerminalResponse) -> bytes:
        pending = self._pending_terminal_sessions.get(pid_used)
        if pending is None:
            raise ValueError("no pending terminal session for PID")

        expected = auth_terminal_to_n(
            pid_to_bytes(pending.new_pid),
            pending.nt,
            pending.nn,
            pending.challenge_new,
            response.r_masked,
            pending.sk_tn,
        )
        if response.auth_tn != expected:
            raise ValueError("terminal authentication tag mismatch")

        mask = mask_response_terminal(pending.id_t_bytes, pending.nn, pending.response_old)
        r_new = xor_bytes(response.r_masked, mask)

        record = self.terminal_records[pending.terminal_id]
        self._commit_terminal_tuple(record, pending.new_pid, pending.challenge_new, r_new)
        record.serving_uav = pending.uav_id
        record.sk_tn = pending.sk_tn

        del self._pending_terminal_sessions[pid_used]
        return pending.sk_tn

    # ---------------------------------------------------------------- handover

    def handle_handover_request(self, request: UAVHandoverUplink) -> object:
        index_entry = self._terminal_pid_index.get(request.pid)
        if index_entry is None:
            signature = hash_bytes(
                b"ren2023/handover/invalid",
                self.public_key,
                request.pid.encode("utf-8"),
            )
            return NCCTerminalIdentityInvalidResponse(request.pid, b"", signature)

        if request.uav_id not in self.uav_records:
            raise ValueError("unknown UAV identifier for handover")

        identifier, slot = index_entry
        record = self.terminal_records[identifier]
        if slot == "backup":
            self._promote_terminal_backup(record)
        if record.sk_tn is None:
            raise ValueError("terminal has no established SK_TN")

        uav_record = self.uav_records[request.uav_id]
        sk_tnu = derive_sk_tnu(uav_record.id_bytes, request.nu, record.sk_tn)
        new_pid = random_pid()
        pid_mask = mask_pid_terminal(record.id_bytes, pid_to_bytes(record.pid), record.sk_tn)
        pid_masked = xor_bytes(pid_to_bytes(new_pid), pid_mask)
        challenge_new = update_challenge(record.id_bytes, record.challenge, record.response)
        id_u_ascii = uav_record.identifier.encode("utf-8")
        cid_nu = xor_bytes(
            id_u_ascii,
            mask_cid_handover(pid_to_bytes(record.pid), sk_tnu, len(id_u_ascii)),
        )
        auth_nu_t = auth_handover_n_to_t(
            pid_to_bytes(record.pid),
            uav_record.id_bytes,
            request.nu,
            pid_masked,
            sk_tnu,
        )

        pending = _PendingHandoverSession(
            terminal_id=record.identifier,
            id_t_bytes=record.id_bytes,
            uav_id=uav_record.identifier,
            id_u_bytes=uav_record.id_bytes,
            old_pid=record.pid,
            new_pid=new_pid,
            challenge_old=record.challenge,
            response_old=record.response,
            challenge_new=challenge_new,
            nu=request.nu,
            sk_tn=record.sk_tn,
            sk_tnu=sk_tnu,
        )
        self._pending_handover_sessions[request.pid] = pending
        self._commit_terminal_tuple(record, new_pid, record.challenge, record.response)

        return NCCUAVHOResponse(cid_nu, pid_masked, sk_tnu, auth_nu_t)

    def mark_handover_complete(self, pid_used: str) -> None:
        pending = self._pending_handover_sessions.get(pid_used)
        if pending is None:
            raise ValueError("no pending handover session for PID")

        payload = _HANDOVER_INBOX.get(pid_used)
        if payload is None:
            raise ValueError("handover payload missing")
        if payload.terminal_id != pending.terminal_id or payload.uav_id != pending.uav_id:
            raise ValueError("handover payload mismatch")
        if payload.sk_tnu != pending.sk_tnu:
            raise ValueError("handover session key mismatch")

        record = self.terminal_records[pending.terminal_id]
        record.pid = payload.pid_new
        record.challenge = payload.challenge_new
        record.response = payload.response_new
        record.serving_uav = pending.uav_id
        record.sk_tn = pending.sk_tn
        self._terminal_pid_index[record.pid] = (record.identifier, "current")
        if record.backup_pid is not None:
            self._terminal_pid_index[record.backup_pid] = (record.identifier, "backup")

        del self._pending_handover_sessions[pid_used]
        _HANDOVER_INBOX.pop(pid_used, None)

    def cancel_handover(self, pid_used: str) -> None:
        self._pending_handover_sessions.pop(pid_used, None)
        _HANDOVER_INBOX.pop(pid_used, None)


################################################################################
# UAV behaviour
################################################################################


@dataclass
class _PendingUAVAuth:
    entry: TupleEntry
    nu: bytes


@dataclass
class _PendingUAVTerminalSession:
    nu: bytes
    sk_tu: Optional[bytes] = None


@dataclass
class _PendingUAVHandoverSession:
    nu: bytes
    sk_tnu: Optional[bytes] = None


class UAV:
    def __init__(self, identifier: str, puf: PUFDevice):
        self.identifier = identifier
        self.puf = puf
        self._id_bytes = identity_bytes(identifier)
        self._id_ascii = identifier.encode("utf-8")
        self.public_key: Optional[bytes] = None
        self.tuple0: Optional[TupleEntry] = None
        self.tuple1: Optional[TupleEntry] = None
        self._pending_auth: Optional[_PendingUAVAuth] = None
        self._pending_terminal: Dict[str, _PendingUAVTerminalSession] = {}
        self._pending_handover: Dict[str, _PendingUAVHandoverSession] = {}

    def complete_registration(self, bundle: RegistrationBundle) -> RegistrationResponse:
        self.public_key = bundle.public_key
        response = self.puf.evaluate(bundle.challenge)
        entry = TupleEntry(bundle.pid, bundle.challenge)
        self.tuple0 = TupleEntry(bundle.pid, bundle.challenge)
        self.tuple1 = entry
        return RegistrationResponse(bundle.pid, bundle.challenge, response)

    def start_auth_phase1(self, *, use_backup_tuple: bool = False) -> UAVAuthRequest:
        entry = self.tuple0 if use_backup_tuple else self.tuple1
        if entry is None:
            raise ValueError("tuple entry unavailable")
        nu = random_bytes(NONCE_SIZE)
        self._pending_auth = _PendingUAVAuth(entry, nu)
        return UAVAuthRequest(entry.pid, nu)

    def handle_invalid_identity(self, response: NCCUAVIdentityInvalidResponse) -> bool:
        if self.public_key is None:
            return False
        expected = hash_bytes(
            b"ren2023/uav/invalid",
            self.public_key,
            response.pid.encode("utf-8"),
            response.nu,
        )
        self._pending_auth = None
        return response.signature == expected

    def complete_auth_phase1(self, response: NCCUAVAuthResponse) -> Tuple[UAVAuthResponse, bytes, str]:
        if self._pending_auth is None:
            raise ValueError("no pending UAV auth session")
        entry = self._pending_auth.entry
        nu = self._pending_auth.nu
        r_old = self.puf.evaluate(entry.challenge)
        session_key = derive_uav_session_key(nu, response.nn, entry.challenge, r_old)

        pid_mask = mask_pid_uav(self._id_bytes, pid_to_bytes(entry.pid), session_key)
        pid_new_bytes = xor_bytes(response.pid_masked, pid_mask)
        pid_new = pid_from_bytes(pid_new_bytes)

        auth_expected = auth_n_to_u(
            pid_to_bytes(entry.pid),
            self._id_bytes,
            nu,
            response.nn,
            response.pid_masked,
            entry.challenge,
            session_key,
        )
        if response.authn_u != auth_expected:
            raise ValueError("NCC authenticity check failed")

        challenge_new = update_challenge(self._id_bytes, entry.challenge, r_old)
        r_new = self.puf.evaluate(challenge_new)
        mask = mask_response_uav(self._id_bytes, response.nn, r_old)
        r_masked = xor_bytes(r_new, mask)
        auth_un = auth_u_to_n(pid_new_bytes, challenge_new, r_masked, session_key)

        self.tuple0 = TupleEntry(entry.pid, entry.challenge)
        self.tuple1 = TupleEntry(pid_new, challenge_new)
        self._pending_auth = None

        return UAVAuthResponse(r_masked, auth_un), session_key, entry.pid

    def forward_terminal_request(self, request: TerminalAuthRequest) -> UAVForwardedTerminalRequest:
        nu = random_bytes(NONCE_SIZE)
        self._pending_terminal[request.pid] = _PendingUAVTerminalSession(nu)
        return UAVForwardedTerminalRequest(request.pid, request.nt, nu, self.identifier)

    def process_terminal_auth_response(self, pid: str, response: object) -> object:
        if not isinstance(response, NCCTerminalAuthResponse):
            return response
        pending = self._pending_terminal.get(pid)
        if pending is None:
            raise ValueError("no pending terminal relay session")
        pending.sk_tu = response.sk_tu
        pid_bytes = pid_to_bytes(pid)
        mask = mask_cid_u(pid_bytes, response.sk_tu, len(self._id_ascii))
        cid_u = xor_bytes(self._id_ascii, mask)
        return UAVToTerminalAuthForward(response.pid_masked, response.nn, pending.nu, cid_u, response.authn_t)

    def forward_terminal_response(self, pid: str, response: TerminalAuthResponse) -> UAVForwardedTerminalResponse:
        pending = self._pending_terminal.get(pid)
        if pending is None or pending.sk_tu is None:
            raise ValueError("no pending terminal relay session")
        expected = auth_terminal_to_u(
            response.r_masked,
            response.auth_tn,
            self._id_bytes,
            pending.nu,
            pending.sk_tu,
        )
        if response.auth_tu != expected:
            raise ValueError("terminal-to-UAV MAC mismatch")
        del self._pending_terminal[pid]
        return UAVForwardedTerminalResponse(response.r_masked, response.auth_tn)

    def receive_handover_request(self, request: TerminalHandoverRequest) -> UAVHandoverUplink:
        nu = random_bytes(NONCE_SIZE)
        self._pending_handover[request.pid] = _PendingUAVHandoverSession(nu)
        return UAVHandoverUplink(request.pid, nu, self.identifier)

    def process_handover_response(self, pid: str, response: object) -> object:
        if not isinstance(response, NCCUAVHOResponse):
            return response
        pending = self._pending_handover.get(pid)
        if pending is None:
            raise ValueError("no pending handover relay session")
        pending.sk_tnu = response.sk_tnu
        expected = auth_handover_n_to_t(
            pid_to_bytes(pid),
            self._id_bytes,
            pending.nu,
            response.pid_masked,
            response.sk_tnu,
        )
        if response.auth_nu_t != expected:
            raise ValueError("handover authenticity failed at UAV")
        return UAVTerHOResponse(pending.nu, response.cid_nu, response.pid_masked, response.sk_tnu, response.auth_nu_t)

    def finalise_handover(self, pid: str, response: TerminalHandoverResponse) -> bytes:
        pending = self._pending_handover.get(pid)
        if pending is None or pending.sk_tnu is None:
            raise ValueError("no pending handover relay session")
        expected = auth_handover_t_to_u(
            self._id_bytes,
            pid_to_bytes(pid),
            pending.nu,
            response.n_t,
            pending.sk_tnu,
        )
        if response.auth_tnu != expected:
            raise ValueError("handover confirmation mismatch")
        del self._pending_handover[pid]
        return pending.sk_tnu


################################################################################
# Terminal behaviour
################################################################################


@dataclass
class _PendingTerminalAuth:
    entry: TupleEntry
    nt: bytes


@dataclass
class _PendingTerminalHandover:
    entry: TupleEntry
    sk_tn: bytes


class Terminal:
    def __init__(self, identifier: str, puf: PUFDevice):
        self.identifier = identifier
        self.puf = puf
        self._id_bytes = identity_bytes(identifier)
        self.public_key: Optional[bytes] = None
        self.tuple0: Optional[TupleEntry] = None
        self.tuple1: Optional[TupleEntry] = None
        self._pending_auth: Optional[_PendingTerminalAuth] = None
        self._pending_handover: Optional[_PendingTerminalHandover] = None
        self._current_sk_tn: Optional[bytes] = None
        self.current_uav_id: Optional[str] = None

    def complete_registration(self, bundle: RegistrationBundle) -> RegistrationResponse:
        self.public_key = bundle.public_key
        response = self.puf.evaluate(bundle.challenge)
        entry = TupleEntry(bundle.pid, bundle.challenge)
        self.tuple0 = TupleEntry(bundle.pid, bundle.challenge)
        self.tuple1 = entry
        return RegistrationResponse(bundle.pid, bundle.challenge, response)

    def start_auth_phase2(self, *, use_backup_tuple: bool = False) -> TerminalAuthRequest:
        entry = self.tuple0 if use_backup_tuple else self.tuple1
        if entry is None:
            raise ValueError("tuple entry unavailable")
        nt = random_bytes(NONCE_SIZE)
        self._pending_auth = _PendingTerminalAuth(entry, nt)
        return TerminalAuthRequest(entry.pid, nt)

    def handle_terminal_invalid_response(self, response: NCCTerminalIdentityInvalidResponse) -> bool:
        if self.public_key is None:
            return False
        expected = hash_bytes(
            b"ren2023/terminal/invalid",
            self.public_key,
            response.pid.encode("utf-8"),
            response.nt,
        )
        self._pending_auth = None
        return response.signature == expected

    def complete_auth_phase2(
        self, response: UAVToTerminalAuthForward
    ) -> Tuple[TerminalAuthResponse, bytes, bytes, str, str]:
        if self._pending_auth is None:
            raise ValueError("no pending terminal authentication")
        entry = self._pending_auth.entry
        nt = self._pending_auth.nt
        r_old = self.puf.evaluate(entry.challenge)
        sk_tn = derive_terminal_sk_tn(nt, response.nn, entry.challenge, r_old)
        sk_tu = derive_terminal_sk_tu(nt, response.nu, sk_tn)

        mask = mask_cid_u(pid_to_bytes(entry.pid), sk_tu, len(response.cid_u))
        id_u_ascii = xor_bytes(response.cid_u, mask)
        id_u = id_u_ascii.decode("utf-8")
        id_u_hash = identity_bytes(id_u)

        auth_expected = auth_n_to_terminal(
            pid_to_bytes(entry.pid),
            self._id_bytes,
            id_u_hash,
            nt,
            response.nu,
            response.nn,
            response.pid_masked,
            entry.challenge,
            sk_tn,
        )
        if response.authn_t != auth_expected:
            raise ValueError("NCC authenticity failed at terminal")

        pid_mask = mask_pid_terminal(self._id_bytes, pid_to_bytes(entry.pid), sk_tn)
        pid_new_bytes = xor_bytes(response.pid_masked, pid_mask)
        pid_new = pid_from_bytes(pid_new_bytes)

        challenge_new = update_challenge(self._id_bytes, entry.challenge, r_old)
        r_new = self.puf.evaluate(challenge_new)
        mask_r = mask_response_terminal(self._id_bytes, response.nn, r_old)
        r_masked = xor_bytes(r_new, mask_r)
        auth_tn = auth_terminal_to_n(pid_new_bytes, nt, response.nn, challenge_new, r_masked, sk_tn)
        auth_tu = auth_terminal_to_u(r_masked, auth_tn, id_u_hash, response.nu, sk_tu)

        self.tuple0 = TupleEntry(entry.pid, entry.challenge)
        self.tuple1 = TupleEntry(pid_new, challenge_new)
        self._pending_auth = None
        self._current_sk_tn = sk_tn
        self.current_uav_id = id_u

        _HANDOVER_INBOX.pop(entry.pid, None)

        return TerminalAuthResponse(r_masked, auth_tn, auth_tu), sk_tn, sk_tu, entry.pid, id_u

    def start_handover(self, *, use_backup_tuple: bool = False) -> TerminalHandoverRequest:
        if self._current_sk_tn is None:
            raise ValueError("handover requires established SK_TN")
        entry = self.tuple0 if use_backup_tuple else self.tuple1
        if entry is None:
            raise ValueError("tuple entry unavailable")
        self._pending_handover = _PendingTerminalHandover(entry, self._current_sk_tn)
        return TerminalHandoverRequest(entry.pid)

    def handle_handover_invalid_response(self, response: NCCUAVHOIdentityInvalidResponse) -> bool:
        if self.public_key is None:
            return False
        expected = hash_bytes(
            b"ren2023/handover/invalid",
            self.public_key,
            response.pid.encode("utf-8"),
        )
        self._pending_handover = None
        return response.signature == expected

    def complete_handover(
        self, response: UAVTerHOResponse
    ) -> Tuple[TerminalHandoverResponse, bytes, str, str]:
        if self._pending_handover is None:
            raise ValueError("no pending handover session")
        entry = self._pending_handover.entry
        sk_tn = self._pending_handover.sk_tn

        cid_mask = mask_cid_handover(pid_to_bytes(entry.pid), response.sk_tnu, len(response.cid_nu))
        id_nu_ascii = xor_bytes(response.cid_nu, cid_mask)
        id_nu = id_nu_ascii.decode("utf-8")
        id_nu_hash = identity_bytes(id_nu)
        sk_tnu = response.sk_tnu
        derived = derive_sk_tnu(id_nu_hash, response.nu, sk_tn)
        if derived != sk_tnu:
            raise ValueError("inconsistent SK_T-nU value")

        auth_expected = auth_handover_n_to_t(
            pid_to_bytes(entry.pid),
            id_nu_hash,
            response.nu,
            response.pid_masked,
            sk_tnu,
        )
        if response.auth_nu_t != auth_expected:
            raise ValueError("handover authenticity failed at terminal")

        pid_mask = mask_pid_terminal(self._id_bytes, pid_to_bytes(entry.pid), sk_tn)
        pid_new_bytes = xor_bytes(response.pid_masked, pid_mask)
        pid_new = pid_from_bytes(pid_new_bytes)

        r_old = self.puf.evaluate(entry.challenge)
        challenge_new = update_challenge(self._id_bytes, entry.challenge, r_old)
        r_new = self.puf.evaluate(challenge_new)
        mask_r = mask_response_handover(self._id_bytes, response.nu, r_old)
        r_masked = xor_bytes(r_new, mask_r)
        n_t = random_bytes(NONCE_SIZE)
        auth_tnu = auth_handover_t_to_u(id_nu_hash, pid_to_bytes(entry.pid), response.nu, n_t, sk_tnu)

        self.tuple0 = TupleEntry(entry.pid, entry.challenge)
        self.tuple1 = TupleEntry(pid_new, challenge_new)
        self._pending_handover = None
        self.current_uav_id = id_nu

        _HANDOVER_INBOX[entry.pid] = _StoredHandoverPayload(
            terminal_id=self.identifier,
            uav_id=id_nu,
            pid_new=pid_new,
            challenge_new=challenge_new,
            response_new=r_new,
            sk_tnu=sk_tnu,
        )

        return TerminalHandoverResponse(n_t, auth_tnu, r_masked), sk_tnu, pid_new, id_nu


__all__ = [
    "PID_SIZE",
    "CHALLENGE_SIZE",
    "SESSION_KEY_SIZE",
    "TupleEntry",
    "RegistrationBundle",
    "RegistrationResponse",
    "PUFDevice",
    "UAVAuthRequest",
    "NCCUAVAuthResponse",
    "NCCUAVIdentityInvalidResponse",
    "UAVAuthResponse",
    "TerminalAuthRequest",
    "UAVForwardedTerminalRequest",
    "NCCTerminalAuthResponse",
    "NCCTerminalIdentityInvalidResponse",
    "UAVToTerminalAuthForward",
    "TerminalAuthResponse",
    "UAVForwardedTerminalResponse",
    "TerminalHandoverRequest",
    "UAVHandoverUplink",
    "NCCUAVHOResponse",
    "NCCUAVHOIdentityInvalidResponse",
    "UAVTerHOResponse",
    "TerminalHandoverResponse",
    "NCC",
    "UAV",
    "Terminal",
]
