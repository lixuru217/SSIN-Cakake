#!/usr/bin/env python3
"""
Implementation of the Guo et al. (2021) SIN access and handover authentication
protocol using MIRACL Core elliptic-curve primitives.

This module models every phase described in the paper, exposing small helper
classes so that simulations can exercise individual message flows:

* System initialisation handled by the trusted NCC
* Registration of satellites, ground stations, and user equipment
* Access authentication across UE → LEO → GS with full equation checks
* Satellite handover while reusing the existing GS session
* Ground station handover, including the batched multi-user variant
* Local password rotation performed by the UE

Each entity keeps track of in-flight sessions so that callers may stitch the
message sequence together without additional global state.  Symmetric channels
are modelled with MIRACL's AES-CTR reference implementation; all hashes are
labelled to avoid collisions between the many dᵢ values defined by the scheme.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from miracl_aes import EncryptedPayload, MiraclCTRChannel

from bn254 import big
from bn254 import curve
from bn254.ecp import ECp, generator

################################################################################
# Encoding and hash helpers
################################################################################


def _encode_length(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def _hash_bytes(label: bytes, *parts: bytes, digest=hashlib.sha256) -> bytes:
    h = digest()
    h.update(label)
    for part in parts:
        h.update(_encode_length(part))
    return h.digest()


def hash_to_scalar(label: bytes, *parts: bytes) -> int:
    digest = _hash_bytes(label, *parts, digest=hashlib.sha512)
    return int.from_bytes(digest, "big") % curve.r


def hash_to_bytes(label: bytes, *parts: bytes) -> bytes:
    return _hash_bytes(label, *parts, digest=hashlib.sha256)


def timestamp_to_bytes(ts: int) -> bytes:
    return ts.to_bytes(12, "big", signed=False)


def scalar_to_bytes(k: int) -> bytes:
    return (k % curve.r).to_bytes(curve.EFS, "big")


def point_to_bytes(P: ECp) -> bytes:
    return P.toBytes(False)


def point_from_bytes(data: bytes) -> ECp:
    P = ECp()
    if not P.fromBytes(data):
        raise ValueError("invalid point encoding")
    return P


def random_scalar() -> int:
    while True:
        candidate = big.rand(curve.r)
        if candidate != 0:
            return candidate


def normalize_scalar(value: int) -> int:
    return value % curve.r


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def point_add(*points: ECp) -> ECp:
    acc: Optional[ECp] = None
    for point in points:
        if acc is None:
            acc = point.copy()
        else:
            acc.add(point)
    if acc is None:
        raise ValueError("no points supplied")
    return acc


def point_sub(P: ECp, Q: ECp) -> ECp:
    result = P.copy()
    result.add(-Q)
    return result


def derive_session_key(point_bytes: bytes) -> bytes:
    return hash_to_bytes(b"Guo2021/session", point_bytes)


def _channel_key(session_key: bytes) -> bytes:
    if len(session_key) >= 32:
        return session_key[:32]
    digest = hashlib.sha256(session_key).digest()
    return digest


def encrypt_with_session(session_key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    key = _channel_key(session_key)
    channel = MiraclCTRChannel(key[:16])
    payload = channel.encrypt(plaintext)
    return payload.nonce, payload.ciphertext


def decrypt_with_session(session_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    key = _channel_key(session_key)
    channel = MiraclCTRChannel(key[:16])
    payload = EncryptedPayload(nonce, ciphertext)
    return channel.decrypt(payload)


def biometric_gen(biometric: bytes) -> Tuple[bytes, bytes]:
    salt = os.urandom(16)
    sigma = hashlib.blake2s(biometric + salt, digest_size=32).digest()
    return sigma, salt


def biometric_rep(biometric: bytes, helper: bytes) -> bytes:
    return hashlib.blake2s(biometric + helper, digest_size=32).digest()


def _hash_list(items: Iterable[bytes]) -> bytes:
    buf = bytearray()
    for item in items:
        buf.extend(_encode_length(item))
    return bytes(buf)


def hash_rpw(password: str, sigma: bytes) -> bytes:
    return hash_to_bytes(b"Guo2021/rpw", password.encode("utf-8"), sigma)


def hash_verifier(user_id: str, tid: str, rpw: bytes, sk_scalar: int) -> bytes:
    return hash_to_bytes(
        b"Guo2021/ver",
        user_id.encode("utf-8"),
        tid.encode("utf-8"),
        rpw,
        scalar_to_bytes(sk_scalar),
    )


def hash_tid(user_id: str, q_scalar: int) -> str:
    tid_bytes = hash_to_bytes(b"Guo2021/tid", user_id.encode("utf-8"), scalar_to_bytes(q_scalar))
    return tid_bytes.hex()


def hash_d1(tid: str, sat_id: str, gs_id: str, pk_i: bytes, T1: int) -> int:
    return hash_to_scalar(
        b"Guo2021/d1",
        tid.encode("utf-8"),
        sat_id.encode("utf-8"),
        gs_id.encode("utf-8"),
        pk_i,
        timestamp_to_bytes(T1),
    )


def hash_d2(tid: str, sat_id: str, gs_id: str, pk_i: bytes, pk_j: bytes, T1: int, T2: int) -> int:
    return hash_to_scalar(
        b"Guo2021/d2",
        tid.encode("utf-8"),
        sat_id.encode("utf-8"),
        gs_id.encode("utf-8"),
        pk_i,
        pk_j,
        timestamp_to_bytes(T1),
        timestamp_to_bytes(T2),
    )


def hash_d3(gs_id: str, sat_id: str, tid: str, shared_bytes: bytes) -> int:
    return hash_to_scalar(
        b"Guo2021/d3",
        gs_id.encode("utf-8"),
        sat_id.encode("utf-8"),
        tid.encode("utf-8"),
        shared_bytes,
    )


def hash_d4(
    gs_id: str,
    sat_id: str,
    tid: str,
    pk_k: bytes,
    alpha_k: int,
    T1: int,
    T2: int,
    T3: int,
) -> int:
    return hash_to_scalar(
        b"Guo2021/d4",
        gs_id.encode("utf-8"),
        sat_id.encode("utf-8"),
        tid.encode("utf-8"),
        pk_k,
        scalar_to_bytes(alpha_k),
        timestamp_to_bytes(T1),
        timestamp_to_bytes(T2),
        timestamp_to_bytes(T3),
    )


def hash_d5(gs_id: str, sat_id: str, tid: str, pk_j: bytes, T4: int) -> int:
    return hash_to_scalar(
        b"Guo2021/d5",
        gs_id.encode("utf-8"),
        sat_id.encode("utf-8"),
        tid.encode("utf-8"),
        pk_j,
        timestamp_to_bytes(T4),
    )


def hash_d6(tid: str, sat_id: str, pk_i1: bytes, T5: int) -> int:
    return hash_to_scalar(
        b"Guo2021/d6",
        tid.encode("utf-8"),
        sat_id.encode("utf-8"),
        pk_i1,
        timestamp_to_bytes(T5),
    )


def hash_d7(tid: str, sat_id: str, pk_n: bytes, T6: int) -> int:
    return hash_to_scalar(
        b"Guo2021/d7",
        tid.encode("utf-8"),
        sat_id.encode("utf-8"),
        pk_n,
        timestamp_to_bytes(T6),
    )


def hash_d8(tids: Sequence[str], gs_id: str, target_id: str, pk_list: Sequence[bytes], pk_k1: bytes, T7: int) -> int:
    parts = [tid.encode("utf-8") for tid in tids]
    pk_concat = _hash_list(pk_list)
    return hash_to_scalar(
        b"Guo2021/d8",
        _hash_list(parts),
        gs_id.encode("utf-8"),
        target_id.encode("utf-8"),
        pk_concat,
        pk_k1,
        timestamp_to_bytes(T7),
    )


def hash_d9(tids: Sequence[str], gs_id: str, target_id: str, pk_t: bytes, T8: int) -> int:
    parts = [tid.encode("utf-8") for tid in tids]
    return hash_to_scalar(
        b"Guo2021/d9",
        _hash_list(parts),
        gs_id.encode("utf-8"),
        target_id.encode("utf-8"),
        pk_t,
        timestamp_to_bytes(T8),
    )


################################################################################
# Dataclasses representing entities and sessions
################################################################################


@dataclass(frozen=True)
class SessionIdentifier:
    tid: str
    satellite_id: str
    ground_id: str


@dataclass
class UserAccessContext:
    session_id: SessionIdentifier
    r_i: int
    pk_i_bytes: bytes
    T1: int
    alpha_i: int
    session_point: Optional[bytes] = None
    session_key: Optional[bytes] = None
    current_satellite: str = ""
    current_ground: str = ""


@dataclass
class SatelliteAccessContext:
    session_id: SessionIdentifier
    r_j: int
    pk_j_bytes: bytes
    T2: int
    alpha_i: int
    alpha_k: Optional[int] = None
    pk_k_bytes: Optional[bytes] = None


@dataclass
class GroundStationAccessContext:
    session_id: SessionIdentifier
    r_k: int
    pk_k_bytes: bytes
    T3: int
    sk_point_bytes: bytes
    session_key: bytes
    pk_i_bytes: bytes
    pk_j_bytes: bytes


@dataclass
class UserSwitchContext:
    session_id: SessionIdentifier
    target_satellite: str
    r_i2: int
    pk_i2_bytes: bytes


@dataclass
class GroundStationSwitchContext:
    session_ids: List[SessionIdentifier]
    target_id: str
    tid_list: List[str]
    pk_i2_list: List[bytes]
    r_k1: int
    pk_k1_bytes: bytes
    T7: int


################################################################################
# Message representations
################################################################################


@dataclass
class MessageM1:
    tid: str
    satellite_id: str
    ground_id: str
    pk_i_bytes: bytes
    alpha_i: int
    T1: int


@dataclass
class MessageM2:
    tid: str
    satellite_id: str
    ground_id: str
    pk_i_bytes: bytes
    pk_j_bytes: bytes
    alpha_j: int
    T1: int
    T2: int


@dataclass
class MessageM3:
    tid: str
    satellite_id: str
    ground_id: str
    pk_i_bytes: bytes
    pk_j_bytes: bytes
    pk_k_bytes: bytes
    alpha_k: int
    alpha_k1: int
    T1: int
    T2: int
    T3: int


@dataclass
class MessageM4:
    tid: str
    satellite_id: str
    ground_id: str
    pk_j_bytes: bytes
    pk_k_bytes: bytes
    alpha_j1: int
    T4: int


@dataclass
class MessageM5:
    tid: str
    satellite_id: str
    pk_i1_bytes: bytes
    alpha_i1: int
    T5: int


@dataclass
class MessageM6:
    tid: str
    satellite_id: str
    pk_n_bytes: bytes
    alpha_n: int
    T6: int


@dataclass
class SwitchRequest:
    tid: str
    nonce: bytes
    ciphertext: bytes


@dataclass
class MessageM8:
    source_gs: str
    target_gs: str
    tid_list: List[str]
    pk_i2_list: List[bytes]
    pk_k1_bytes: bytes
    alpha_k1: int
    T7: int


@dataclass
class MessageM9:
    source_gs: str
    target_gs: str
    pk_t_bytes: bytes
    alpha_t1: int
    T8: int


@dataclass
class MessageM10:
    tid: str
    nonce: bytes
    ciphertext: bytes


@dataclass
class AccessResult:
    session_id: SessionIdentifier
    shared_point_bytes: bytes
    session_key: bytes


################################################################################
# NCC state and entity registrations
################################################################################


@dataclass
class SatellitePublicRecord:
    satellite_id: str
    pk_bytes: bytes


@dataclass
class GroundStationPublicRecord:
    ground_id: str
    pk_bytes: bytes


@dataclass
class UserPublicRecord:
    user_id: str
    tid: str
    pk_bytes: bytes


@dataclass
class NCCState:
    master_secret: int = field(default_factory=random_scalar)
    pk_bytes: bytes = field(init=False)
    satellites: Dict[str, SatellitePublicRecord] = field(default_factory=dict)
    ground_stations: Dict[str, GroundStationPublicRecord] = field(default_factory=dict)
    users_by_tid: Dict[str, UserPublicRecord] = field(default_factory=dict)
    users_by_id: Dict[str, UserPublicRecord] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.pk_bytes = point_to_bytes(self.master_secret * generator())

    def public_point(self) -> ECp:
        return point_from_bytes(self.pk_bytes)

    def register_satellite(self, satellite_id: str) -> "SatelliteState":
        q_j = random_scalar()
        pk_point = q_j * generator()
        pk_bytes = point_to_bytes(pk_point)
        sk_j = normalize_scalar(q_j + self.master_secret)
        self.satellites[satellite_id] = SatellitePublicRecord(satellite_id, pk_bytes)
        return SatelliteState(
            ncc=self,
            satellite_id=satellite_id,
            q_scalar=q_j,
            sk_scalar=sk_j,
            pk_bytes=pk_bytes,
        )

    def register_ground_station(self, ground_id: str) -> "GroundStationState":
        q_k = random_scalar()
        pk_point = q_k * generator()
        pk_bytes = point_to_bytes(pk_point)
        sk_k = normalize_scalar(q_k + self.master_secret)
        self.ground_stations[ground_id] = GroundStationPublicRecord(ground_id, pk_bytes)
        return GroundStationState(
            ncc=self,
            ground_id=ground_id,
            q_scalar=q_k,
            sk_scalar=sk_k,
            pk_bytes=pk_bytes,
        )

    def register_user(self, user_id: str, password: str, biometric: bytes) -> "UserDeviceState":
        sigma, helper = biometric_gen(biometric)
        rpw = hash_rpw(password, sigma)

        q_i = random_scalar()
        pk_point = q_i * generator()
        pk_bytes = point_to_bytes(pk_point)
        tid = hash_tid(user_id, q_i)
        sk_i = normalize_scalar(q_i + self.master_secret)
        sk_bytes = scalar_to_bytes(sk_i)
        dp_bytes = xor_bytes(rpw, sk_bytes)
        verifier = hash_verifier(user_id, tid, rpw, sk_i)

        public_record = UserPublicRecord(user_id, tid, pk_bytes)
        self.users_by_tid[tid] = public_record
        self.users_by_id[user_id] = public_record

        recovered_sk = int.from_bytes(xor_bytes(dp_bytes, rpw), "big") % curve.r
        if recovered_sk != sk_i:
            raise ValueError("registration failed to recover SK")

        return UserDeviceState(
            ncc=self,
            user_id=user_id,
            tid=tid,
            pk_bytes=pk_bytes,
            dp_bytes=dp_bytes,
            v_bytes=helper,
            verifier=verifier,
            sigma=sigma,
            rpw=rpw,
            sk_scalar=sk_i,
        )

    def get_user_public(self, tid: str) -> UserPublicRecord:
        return self.users_by_tid[tid]

    def get_satellite_public(self, satellite_id: str) -> SatellitePublicRecord:
        return self.satellites[satellite_id]

    def get_ground_public(self, ground_id: str) -> GroundStationPublicRecord:
        return self.ground_stations[ground_id]


################################################################################
# Entity representations
################################################################################


@dataclass
class SatelliteState:
    ncc: NCCState
    satellite_id: str
    q_scalar: int
    sk_scalar: int
    pk_bytes: bytes
    sessions: Dict[SessionIdentifier, SatelliteAccessContext] = field(default_factory=dict)

    def process_m1(
        self,
        message: MessageM1,
        now: int,
        tolerance: int,
    ) -> MessageM2:
        if abs(now - message.T1) > tolerance:
            raise ValueError("M1 timestamp expired")
        session_id = SessionIdentifier(message.tid, message.satellite_id, message.ground_id)

        pk_i_point = point_from_bytes(message.pk_i_bytes)
        user_record = self.ncc.get_user_public(message.tid)
        pk_i_public = point_from_bytes(user_record.pk_bytes)
        pk_ncc = self.ncc.public_point()

        d1_prime = hash_d1(message.tid, message.satellite_id, message.ground_id, message.pk_i_bytes, message.T1)
        lhs_point = message.alpha_i * generator()
        rhs_point = point_add(
            pk_i_public,
            d1_prime * pk_i_point,
            pk_ncc,
        )
        if point_to_bytes(lhs_point) != point_to_bytes(rhs_point):
            raise ValueError("Equation A failed at satellite")

        T2 = now
        r_j = random_scalar()
        pk_j_point = r_j * generator()
        pk_j_bytes = point_to_bytes(pk_j_point)
        d2 = hash_d2(message.tid, message.satellite_id, message.ground_id, message.pk_i_bytes, pk_j_bytes, message.T1, T2)
        alpha_j = normalize_scalar(message.alpha_i - self.sk_scalar + d2 * r_j)
        context = SatelliteAccessContext(
            session_id=session_id,
            r_j=r_j,
            pk_j_bytes=pk_j_bytes,
            T2=T2,
            alpha_i=message.alpha_i,
        )
        self.sessions[session_id] = context
        return MessageM2(
            tid=message.tid,
            satellite_id=message.satellite_id,
            ground_id=message.ground_id,
            pk_i_bytes=message.pk_i_bytes,
            pk_j_bytes=pk_j_bytes,
            alpha_j=alpha_j,
            T1=message.T1,
            T2=T2,
        )

    def process_m3(
        self,
        message: MessageM3,
        now: int,
        tolerance: int,
    ) -> MessageM4:
        session_id = SessionIdentifier(message.tid, message.satellite_id, message.ground_id)
        context = self.sessions.get(session_id)
        if context is None:
            raise ValueError("unknown session at satellite")
        if abs(now - message.T3) > tolerance:
            raise ValueError("M3 timestamp expired")

        pk_k_point = point_from_bytes(message.pk_k_bytes)
        pk_k_public = point_from_bytes(self.ncc.get_ground_public(session_id.ground_id).pk_bytes)
        pk_ncc = self.ncc.public_point()

        d4_prime = hash_d4(
            session_id.ground_id,
            session_id.satellite_id,
            session_id.tid,
            message.pk_k_bytes,
            message.alpha_k,
            message.T1,
            message.T2,
            message.T3,
        )
        lhs_point = message.alpha_k1 * generator()
        rhs_point = point_add(
            pk_k_public,
            d4_prime * pk_k_point,
            pk_ncc,
        )
        if point_to_bytes(lhs_point) != point_to_bytes(rhs_point):
            raise ValueError("Equation C failed at satellite")

        T4 = now
        d5 = hash_d5(session_id.ground_id, session_id.satellite_id, session_id.tid, context.pk_j_bytes, T4)
        alpha_j1 = normalize_scalar(message.alpha_k - self.sk_scalar + d5 * context.r_j)
        context.alpha_k = message.alpha_k
        context.pk_k_bytes = message.pk_k_bytes

        return MessageM4(
            tid=session_id.tid,
            satellite_id=session_id.satellite_id,
            ground_id=session_id.ground_id,
            pk_j_bytes=context.pk_j_bytes,
            pk_k_bytes=message.pk_k_bytes,
            alpha_j1=alpha_j1,
            T4=T4,
        )


@dataclass
class GroundStationState:
    ncc: NCCState
    ground_id: str
    q_scalar: int
    sk_scalar: int
    pk_bytes: bytes
    sessions: Dict[SessionIdentifier, GroundStationAccessContext] = field(default_factory=dict)

    def process_m2(
        self,
        message: MessageM2,
        now: int,
        tolerance_inner: int,
        tolerance_outer: int,
    ) -> MessageM3:
        if abs(now - message.T2) > tolerance_inner or abs(now - message.T1) > tolerance_outer:
            raise ValueError("M2 timestamps invalid at ground station")

        session_id = SessionIdentifier(message.tid, message.satellite_id, message.ground_id)
        pk_i_point = point_from_bytes(message.pk_i_bytes)
        pk_j_point = point_from_bytes(message.pk_j_bytes)

        user_record = self.ncc.get_user_public(message.tid)
        pk_i_public = point_from_bytes(user_record.pk_bytes)
        sat_record = self.ncc.get_satellite_public(message.satellite_id)
        pk_j_public = point_from_bytes(sat_record.pk_bytes)

        d1_prime = hash_d1(message.tid, message.satellite_id, message.ground_id, message.pk_i_bytes, message.T1)
        d2_prime = hash_d2(message.tid, message.satellite_id, message.ground_id, message.pk_i_bytes, message.pk_j_bytes, message.T1, message.T2)

        lhs_point = message.alpha_j * generator()
        rhs_point = point_add(
            point_sub(pk_i_public, pk_j_public),
            d1_prime * pk_i_point,
            d2_prime * pk_j_point,
        )
        if point_to_bytes(lhs_point) != point_to_bytes(rhs_point):
            raise ValueError("Equation B failed at ground station")

        T3 = now
        r_k = random_scalar()
        pk_k_point = r_k * generator()
        pk_k_bytes = point_to_bytes(pk_k_point)
        shared_point = r_k * pk_i_point
        shared_bytes = point_to_bytes(shared_point)
        d3 = hash_d3(self.ground_id, message.satellite_id, message.tid, shared_bytes)
        alpha_k = normalize_scalar(self.sk_scalar + d3 * r_k)
        d4 = hash_d4(self.ground_id, message.satellite_id, message.tid, pk_k_bytes, alpha_k, message.T1, message.T2, T3)
        alpha_k1 = normalize_scalar(self.sk_scalar + d4 * r_k)

        session_key = derive_session_key(shared_bytes)
        context = GroundStationAccessContext(
            session_id=session_id,
            r_k=r_k,
            pk_k_bytes=pk_k_bytes,
            T3=T3,
            sk_point_bytes=shared_bytes,
            session_key=session_key,
            pk_i_bytes=message.pk_i_bytes,
            pk_j_bytes=message.pk_j_bytes,
        )
        self.sessions[session_id] = context

        return MessageM3(
            tid=message.tid,
            satellite_id=message.satellite_id,
            ground_id=message.ground_id,
            pk_i_bytes=message.pk_i_bytes,
            pk_j_bytes=message.pk_j_bytes,
            pk_k_bytes=pk_k_bytes,
            alpha_k=alpha_k,
            alpha_k1=alpha_k1,
            T1=message.T1,
            T2=message.T2,
            T3=T3,
        )

    def get_session(self, session_id: SessionIdentifier) -> GroundStationAccessContext:
        context = self.sessions.get(session_id)
        if context is None:
            raise ValueError("ground station session unknown")
        return context

    def prepare_gs_switch(
        self,
        requests: Sequence[SwitchRequest],
        target_ground_id: str,
        T7: int,
    ) -> Tuple[MessageM8, GroundStationSwitchContext]:
        if not requests:
            raise ValueError("no switch requests provided")
        tid_list: List[str] = []
        pk_i2_list: List[bytes] = []
        session_ids: List[SessionIdentifier] = []
        for item in requests:
            context = self._resolve_session(item.tid)
            plaintext = decrypt_with_session(context.session_key, item.nonce, item.ciphertext)
            target_bytes = target_ground_id.encode("utf-8")
            if not plaintext.startswith(target_bytes):
                raise ValueError("switch request target mismatch")
            pk_i2_bytes = plaintext[len(target_bytes):]
            if not pk_i2_bytes:
                raise ValueError("switch request missing pk_i2 payload")
            point_from_bytes(pk_i2_bytes)  # validation
            tid_list.append(item.tid)
            pk_i2_list.append(pk_i2_bytes)
            session_ids.append(context.session_id)

        r_k1 = random_scalar()
        pk_k1_point = r_k1 * generator()
        pk_k1_bytes = point_to_bytes(pk_k1_point)
        alpha_k1 = normalize_scalar(
            self.sk_scalar + hash_d8(tid_list, self.ground_id, target_ground_id, pk_i2_list, pk_k1_bytes, T7) * r_k1
        )

        message = MessageM8(
            source_gs=self.ground_id,
            target_gs=target_ground_id,
            tid_list=tid_list,
            pk_i2_list=pk_i2_list,
            pk_k1_bytes=pk_k1_bytes,
            alpha_k1=alpha_k1,
            T7=T7,
        )
        context = GroundStationSwitchContext(
            session_ids=session_ids,
            target_id=target_ground_id,
            tid_list=tid_list,
            pk_i2_list=pk_i2_list,
            r_k1=r_k1,
            pk_k1_bytes=pk_k1_bytes,
            T7=T7,
        )
        return message, context

    def process_m9(
        self,
        context: GroundStationSwitchContext,
        message: MessageM9,
        now: int,
        tolerance: int,
    ) -> List[MessageM10]:
        if abs(now - message.T8) > tolerance:
            raise ValueError("M9 timestamp invalid at source GS")
        if message.source_gs != self.ground_id or message.target_gs != context.target_id:
            raise ValueError("M9 identifiers mismatch")

        pk_k_public = point_from_bytes(self.ncc.get_ground_public(self.ground_id).pk_bytes)
        pk_k1_point = point_from_bytes(context.pk_k1_bytes)
        lhs_point = message.alpha_t1 * generator()
        d8_prime = hash_d8(
            context.tid_list,
            self.ground_id,
            context.target_id,
            context.pk_i2_list,
            context.pk_k1_bytes,
            context.T7,
        )
        rhs_point = point_add(
            pk_k_public,
            d8_prime * pk_k1_point,
            self.ncc.public_point(),
        )
        if point_to_bytes(lhs_point) != point_to_bytes(rhs_point):
            raise ValueError("GS switch verification failed at source GS")

        switch_messages: List[MessageM10] = []
        for session_id, tid in zip(context.session_ids, context.tid_list):
            session = self.sessions[session_id]
            target_bytes = context.target_id.encode("utf-8")
            payload = target_bytes + message.pk_t_bytes
            nonce, ciphertext = encrypt_with_session(session.session_key, payload)
            switch_messages.append(MessageM10(tid=tid, nonce=nonce, ciphertext=ciphertext))
        return switch_messages

    def _resolve_session(self, tid: str) -> GroundStationAccessContext:
        for session in self.sessions.values():
            if session.session_id.tid == tid:
                return session
        raise ValueError("no active session for tid")


@dataclass
class UserDeviceState:
    ncc: NCCState
    user_id: str
    tid: str
    pk_bytes: bytes
    dp_bytes: bytes
    v_bytes: bytes
    verifier: bytes
    sigma: bytes
    rpw: bytes
    sk_scalar: int
    sessions: Dict[SessionIdentifier, UserAccessContext] = field(default_factory=dict)
    switch_contexts: Dict[str, UserSwitchContext] = field(default_factory=dict)

    def validate_local_login(self, password: str, biometric: bytes) -> bool:
        sigma_star = biometric_rep(biometric, self.v_bytes)
        rpw_star = hash_rpw(password, sigma_star)
        sk_bytes = xor_bytes(self.dp_bytes, rpw_star)
        sk_recovered = int.from_bytes(sk_bytes, "big") % curve.r
        if sk_recovered != self.sk_scalar:
            return False
        expected = hash_verifier(self.user_id, self.tid, rpw_star, sk_recovered)
        return expected == self.verifier

    def start_access(
        self,
        satellite_id: str,
        ground_id: str,
        T1: int,
    ) -> MessageM1:
        session_id = SessionIdentifier(self.tid, satellite_id, ground_id)
        r_i = random_scalar()
        pk_i_point = r_i * generator()
        pk_i_bytes = point_to_bytes(pk_i_point)
        d1 = hash_d1(self.tid, satellite_id, ground_id, pk_i_bytes, T1)
        alpha_i = normalize_scalar(self.sk_scalar + d1 * r_i)
        context = UserAccessContext(
            session_id=session_id,
            r_i=r_i,
            pk_i_bytes=pk_i_bytes,
            T1=T1,
            alpha_i=alpha_i,
            current_satellite=satellite_id,
            current_ground=ground_id,
        )
        self.sessions[session_id] = context
        return MessageM1(
            tid=self.tid,
            satellite_id=satellite_id,
            ground_id=ground_id,
            pk_i_bytes=pk_i_bytes,
            alpha_i=alpha_i,
            T1=T1,
        )

    def finalize_access(
        self,
        message: MessageM4,
        now: int,
        tolerance: int,
    ) -> AccessResult:
        if abs(now - message.T4) > tolerance:
            raise ValueError("M4 timestamp invalid at UE")
        session_id = SessionIdentifier(message.tid, message.satellite_id, message.ground_id)
        context = self.sessions.get(session_id)
        if context is None:
            raise ValueError("unknown session at UE")

        pk_k_point = point_from_bytes(message.pk_k_bytes)
        pk_j_point = point_from_bytes(message.pk_j_bytes)
        pk_k_public = point_from_bytes(self.ncc.get_ground_public(message.ground_id).pk_bytes)
        pk_j_public = point_from_bytes(self.ncc.get_satellite_public(message.satellite_id).pk_bytes)
        shared_point = context.r_i * pk_k_point
        shared_bytes = point_to_bytes(shared_point)

        d3_prime = hash_d3(message.ground_id, message.satellite_id, message.tid, shared_bytes)
        d5_prime = hash_d5(message.ground_id, message.satellite_id, message.tid, message.pk_j_bytes, message.T4)
        lhs_point = message.alpha_j1 * generator()
        rhs_point = point_add(
            point_sub(pk_k_public, pk_j_public),
            d3_prime * pk_k_point,
            d5_prime * pk_j_point,
        )
        if point_to_bytes(lhs_point) != point_to_bytes(rhs_point):
            raise ValueError("Equation D failed at UE")

        session_key = derive_session_key(shared_bytes)
        context.session_point = shared_bytes
        context.session_key = session_key
        return AccessResult(session_id=session_id, shared_point_bytes=shared_bytes, session_key=session_key)

    def prepare_satellite_switch(
        self,
        session: SessionIdentifier,
        target_satellite: str,
        T5: int,
    ) -> MessageM5:
        context = self.sessions.get(session)
        if context is None:
            raise ValueError("no session for satellite switch")
        r_i2 = random_scalar()
        pk_i1_point = r_i2 * generator()
        pk_i1_bytes = point_to_bytes(pk_i1_point)
        d6 = hash_d6(self.tid, target_satellite, pk_i1_bytes, T5)
        alpha_i1 = normalize_scalar(self.sk_scalar + d6 * r_i2)
        self.switch_contexts[target_satellite] = UserSwitchContext(
            session_id=session,
            target_satellite=target_satellite,
            r_i2=r_i2,
            pk_i2_bytes=pk_i1_bytes,
        )
        return MessageM5(
            tid=self.tid,
            satellite_id=target_satellite,
            pk_i1_bytes=pk_i1_bytes,
            alpha_i1=alpha_i1,
            T5=T5,
        )

    def finalize_satellite_switch(
        self,
        target_satellite: str,
        message: MessageM6,
        now: int,
        tolerance: int,
    ) -> None:
        if abs(now - message.T6) > tolerance:
            raise ValueError("M6 timestamp invalid at UE")
        context = self.switch_contexts.get(target_satellite)
        if context is None:
            raise ValueError("missing satellite switch context")
        pk_n_point = point_from_bytes(message.pk_n_bytes)
        pk_n_public = point_from_bytes(self.ncc.get_satellite_public(target_satellite).pk_bytes)
        pk_ncc = self.ncc.public_point()
        d7_prime = hash_d7(self.tid, target_satellite, message.pk_n_bytes, message.T6)
        lhs_point = message.alpha_n * generator()
        rhs_point = point_add(
            pk_n_public,
            d7_prime * pk_n_point,
            pk_ncc,
        )
        if point_to_bytes(lhs_point) != point_to_bytes(rhs_point):
            raise ValueError("satellite switch equality failed at UE")

        session_id = context.session_id
        session_ctx = self.sessions[session_id]
        new_session_id = SessionIdentifier(self.tid, target_satellite, session_ctx.current_ground)
        session_ctx.current_satellite = target_satellite
        self.sessions[new_session_id] = session_ctx
        if new_session_id != session_id:
            del self.sessions[session_id]
        del self.switch_contexts[target_satellite]

    def prepare_ground_switch_request(
        self,
        session: SessionIdentifier,
        target_ground: str,
    ) -> SwitchRequest:
        context = self.sessions.get(session)
        if context is None or context.session_key is None:
            raise ValueError("session not ready for ground switch")
        r_i2 = random_scalar()
        pk_i2_point = r_i2 * generator()
        pk_i2_bytes = point_to_bytes(pk_i2_point)
        payload = target_ground.encode("utf-8") + pk_i2_bytes
        nonce, ciphertext = encrypt_with_session(context.session_key, payload)
        self.switch_contexts[target_ground] = UserSwitchContext(
            session_id=session,
            target_satellite=context.current_satellite,
            r_i2=r_i2,
            pk_i2_bytes=pk_i2_bytes,
        )
        return SwitchRequest(tid=self.tid, nonce=nonce, ciphertext=ciphertext)

    def process_ground_switch_confirmation(
        self,
        target_ground: str,
        message: MessageM10,
    ) -> None:
        context = self.switch_contexts.get(target_ground)
        if context is None:
            raise ValueError("no pending ground switch context")
        session = self.sessions[context.session_id]
        plaintext = decrypt_with_session(session.session_key, message.nonce, message.ciphertext)
        target_bytes = target_ground.encode("utf-8")
        received_target = plaintext[: len(target_bytes)]
        if received_target != target_bytes:
            raise ValueError("ground switch target mismatch")
        pk_t_bytes = plaintext[len(target_bytes):]
        pk_t_point = point_from_bytes(pk_t_bytes)
        shared_point = context.r_i2 * pk_t_point
        shared_bytes = point_to_bytes(shared_point)
        session.session_key = derive_session_key(shared_bytes)
        session.session_point = shared_bytes
        session.current_ground = target_ground
        new_session_id = SessionIdentifier(self.tid, session.current_satellite, target_ground)
        self.sessions[new_session_id] = session
        if new_session_id != context.session_id:
            del self.sessions[context.session_id]
        del self.switch_contexts[target_ground]

    def rotate_password(self, old_password: str, old_biometric: bytes, new_password: str) -> None:
        if not self.validate_local_login(old_password, old_biometric):
            raise ValueError("local verification failed before password rotation")
        sigma_star = biometric_rep(old_biometric, self.v_bytes)
        new_rpw = hash_rpw(new_password, sigma_star)
        new_dp = xor_bytes(new_rpw, scalar_to_bytes(self.sk_scalar))
        new_verifier = hash_verifier(self.user_id, self.tid, new_rpw, self.sk_scalar)
        self.rpw = new_rpw
        self.dp_bytes = new_dp
        self.verifier = new_verifier


################################################################################
# Ground station (target) handling for switches
################################################################################


def process_ground_switch_at_target(
    ncc: NCCState,
    message: MessageM8,
    now: int,
    tolerance: int,
    target_state: GroundStationState,
) -> Tuple[MessageM9, bytes]:
    if abs(now - message.T7) > tolerance:
        raise ValueError("M8 timestamp invalid at target GS")
    pk_k_public = point_from_bytes(ncc.get_ground_public(message.source_gs).pk_bytes)
    pk_k1_point = point_from_bytes(message.pk_k1_bytes)
    lhs_point = message.alpha_k1 * generator()
    d8_prime = hash_d8(message.tid_list, message.source_gs, message.target_gs, message.pk_i2_list, message.pk_k1_bytes, message.T7)
    rhs_point = point_add(
        pk_k_public,
        d8_prime * pk_k1_point,
        ncc.public_point(),
    )
    if point_to_bytes(lhs_point) != point_to_bytes(rhs_point):
        raise ValueError("target GS verification failed")

    r_t = random_scalar()
    pk_t_point = r_t * generator()
    pk_t_bytes = point_to_bytes(pk_t_point)
    d9 = hash_d9(message.tid_list, message.source_gs, message.target_gs, pk_t_bytes, now)
    alpha_t1 = normalize_scalar(target_state.sk_scalar + d9 * r_t)

    return MessageM9(
        source_gs=message.source_gs,
        target_gs=message.target_gs,
        pk_t_bytes=pk_t_bytes,
        alpha_t1=alpha_t1,
        T8=now,
    ), pk_t_bytes


################################################################################
# Convenience helper to run full access authentication
################################################################################


def run_access_handshake(
    user: UserDeviceState,
    satellite: SatelliteState,
    ground: GroundStationState,
    *,
    T1: int,
    tolerance_sat: int,
    tolerance_gs_inner: int,
    tolerance_gs_outer: int,
    tolerance_user: int,
) -> AccessResult:
    m1 = user.start_access(satellite.satellite_id, ground.ground_id, T1)
    m2 = satellite.process_m1(m1, now=T1, tolerance=tolerance_sat)
    m3 = ground.process_m2(m2, now=m2.T2, tolerance_inner=tolerance_gs_inner, tolerance_outer=tolerance_gs_outer)
    m4 = satellite.process_m3(m3, now=m3.T3, tolerance=tolerance_sat)
    result = user.finalize_access(m4, now=m4.T4, tolerance=tolerance_user)
    return result


################################################################################
# Simple self-test when executed directly
################################################################################


def _self_check() -> None:
    ncc = NCCState()
    sat = ncc.register_satellite("L-01")
    gs = ncc.register_ground_station("GS-01")
    ue = ncc.register_user("UE-01", "hunter2", b"biometric-sample")
    if not ue.validate_local_login("hunter2", b"biometric-sample"):
        raise RuntimeError("local login failed in self-check")
    result = run_access_handshake(
        ue,
        sat,
        gs,
        T1=123456789,
        tolerance_sat=5,
        tolerance_gs_inner=5,
        tolerance_gs_outer=10,
        tolerance_user=5,
    )
    assert result.session_key, "session key not derived"


if __name__ == "__main__":
    _self_check()
