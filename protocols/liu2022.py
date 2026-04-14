#!/usr/bin/env python3
"""
Implementation of the Liu et al. (2022) satellite-to-ground integrated network
access and handover authentication scheme using MIRACL Core primitives.

The module models the main phases described in the paper:
1. System initialisation handled by the trusted NCC
2. Registration of UEs, APs, and GMs together with blind-factor management
3. Group key negotiation between APs and the GM
4. Access authentication and identity refresh between UE and AP
5. Intra-layer handover reusing the lightweight access credentials (LKA)

All scalar and elliptic-curve operations are performed explicitly so that the
simulators can exercise the same algebraic checks as the original scheme.
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from miracl_aes import EncryptedPayload, MiraclCTRChannel

from bn254 import big
from bn254 import curve
from bn254.ecp import ECp, generator

###############################################################################
# Encoding helpers
###############################################################################


def _ensure_bytes(value: bytes | bytearray | str | int) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, int):
        width = max(1, (value.bit_length() + 7) // 8)
        return value.to_bytes(width, "big", signed=False)
    raise TypeError(f"unsupported type {type(value)!r}")


def _encode_length(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _hash_bytes(label: bytes, *parts: bytes, digest=hashlib.sha512) -> bytes:
    h = digest()
    h.update(label)
    for part in parts:
        h.update(_encode_length(part))
    return h.digest()


def hash_h2(*parts: bytes | str | int) -> int:
    digest = _hash_bytes(b"Liu2022/h2", *(_ensure_bytes(p) for p in parts), digest=hashlib.sha512)
    return int.from_bytes(digest, "big") % curve.r


def hash_h1(*parts: bytes | str | int) -> bytes:
    return _hash_bytes(b"Liu2022/h1", *(_ensure_bytes(p) for p in parts), digest=hashlib.sha256)


def kdf(key: bytes, *context: bytes | str | int, length: int = 32) -> bytes:
    hasher = hashlib.blake2s(digest_size=length)
    hasher.update(_encode_length(key))
    for part in context:
        hasher.update(_encode_length(_ensure_bytes(part)))
    return hasher.digest()


def timestamp_to_bytes(ts: int) -> bytes:
    return ts.to_bytes(12, "big", signed=False)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def random_scalar() -> int:
    while True:
        candidate = big.rand(curve.r)
        if candidate != 0:
            return candidate


def normalize_scalar(value: int) -> int:
    return value % curve.r


def scalar_to_bytes(value: int) -> bytes:
    return normalize_scalar(value).to_bytes(curve.EFS, "big")


def point_to_bytes(point: ECp) -> bytes:
    return point.toBytes(False)


def point_from_bytes(data: bytes) -> ECp:
    point = ECp()
    if not point.fromBytes(data):
        raise ValueError("invalid point encoding")
    return point


def derive_session_key(point_bytes: bytes) -> bytes:
    return _hash_bytes(b"Liu2022/session", point_bytes, digest=hashlib.sha256)


def _channel_key(session_key: bytes) -> bytes:
    if len(session_key) >= 32:
        return session_key[:32]
    return hashlib.sha256(session_key).digest()


def encrypt_with_key(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    cipher = MiraclCTRChannel(_channel_key(key)[:16])
    payload = cipher.encrypt(plaintext)
    return payload.nonce, payload.ciphertext


def decrypt_with_key(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    cipher = MiraclCTRChannel(_channel_key(key)[:16])
    payload = EncryptedPayload(nonce, ciphertext)
    return cipher.decrypt(payload)


def modulus_inverse(value: int, modulus: int) -> int:
    if value == 0:
        raise ValueError("cannot invert zero")
    return pow(value, modulus - 2, modulus)


def evaluate_polynomial(coefficients: Sequence[int], x: int, modulus: int) -> int:
    acc = 0
    for coeff in coefficients:
        acc = (acc * x + coeff) % modulus
    return acc


def encode_identity_bytes(identifier: str) -> bytes:
    return identifier.encode("utf-8")


def decode_identity_bytes(data: bytes) -> str:
    return data.decode("utf-8")


def encode_coefficients(coefficients: Sequence[int]) -> bytes:
    size = (GROUP_MODULUS.bit_length() + 7) // 8
    buf = bytearray()
    for coeff in coefficients:
        buf.extend(_encode_length(int(coeff % GROUP_MODULUS).to_bytes(size, "big")))
    return bytes(buf)


def encode_hac(credentials: Sequence["GroupCredential"]) -> bytes:
    return _encode_length(b"".join(item.encode_for_signature() for item in credentials))


def pack_identity_update(identity: MaskedIdentity) -> bytes:
    return identity.encode_for_hash()


def unpack_identity_update(data: bytes) -> MaskedIdentity:
    view = memoryview(data)
    offset = 0
    if len(view) < 4:
        raise ValueError("identity payload truncated")
    pid_len = int.from_bytes(view[offset : offset + 4], "big")
    offset += 4
    if offset + pid_len > len(view):
        raise ValueError("identity payload truncated (p_id)")
    p_id = view[offset : offset + pid_len].tobytes()
    offset += pid_len
    if offset + 4 > len(view):
        raise ValueError("identity payload truncated (index_id)")
    index_id = int.from_bytes(view[offset : offset + 4], "big")
    offset += 4
    if offset + 4 > len(view):
        raise ValueError("identity payload truncated (p_pk len)")
    ppk_len = int.from_bytes(view[offset : offset + 4], "big")
    offset += 4
    if offset + ppk_len > len(view):
        raise ValueError("identity payload truncated (p_pk)")
    p_pk = view[offset : offset + ppk_len].tobytes()
    offset += ppk_len
    if offset + 4 > len(view):
        raise ValueError("identity payload truncated (index_pk)")
    index_pk = int.from_bytes(view[offset : offset + 4], "big")
    offset += 4
    if offset != len(view):
        raise ValueError("unexpected trailing data in identity payload")
    return MaskedIdentity(p_id=p_id, index_id=index_id, p_pk=p_pk, index_pk=index_pk)


def pack_handover_identity(p_id: bytes, index_id: int) -> bytes:
    return _encode_length(p_id) + struct.pack(">I", index_id)


def unpack_handover_identity(data: bytes) -> Tuple[bytes, int]:
    view = memoryview(data)
    if len(view) < 4:
        raise ValueError("handover identity truncated")
    pid_len = int.from_bytes(view[0:4], "big")
    offset = 4
    if offset + pid_len + 4 != len(view):
        raise ValueError("handover identity malformed")
    p_id = view[offset : offset + pid_len].tobytes()
    offset += pid_len
    index_id = int.from_bytes(view[offset : offset + 4], "big")
    return p_id, index_id


def pack_lka_payload(session_key: bytes, ue_id: str, expiry_ts: int) -> bytes:
    return b"".join(
        [
            _encode_length(session_key),
            _encode_length(ue_id.encode("utf-8")),
            struct.pack(">Q", expiry_ts if expiry_ts >= 0 else 0),
        ]
    )


def unpack_lka_payload(data: bytes) -> Tuple[bytes, str, int]:
    view = memoryview(data)
    offset = 0
    if offset + 4 > len(view):
        raise ValueError("lka payload truncated (session len)")
    sess_len = int.from_bytes(view[offset : offset + 4], "big")
    offset += 4
    if offset + sess_len > len(view):
        raise ValueError("lka payload truncated (session data)")
    session_key = view[offset : offset + sess_len].tobytes()
    offset += sess_len
    if offset + 4 > len(view):
        raise ValueError("lka payload truncated (ue len)")
    ue_len = int.from_bytes(view[offset : offset + 4], "big")
    offset += 4
    if offset + ue_len > len(view):
        raise ValueError("lka payload truncated (ue data)")
    ue_id = view[offset : offset + ue_len].tobytes().decode("utf-8")
    offset += ue_len
    if offset + 8 > len(view):
        raise ValueError("lka payload truncated (expiry)")
    expiry_ts = int.from_bytes(view[offset : offset + 8], "big")
    offset += 8
    if offset != len(view):
        raise ValueError("unexpected trailing data in lka payload")
    return session_key, ue_id, expiry_ts


###############################################################################
# Dataclasses for protocol messages and local state
###############################################################################


GROUP_MODULUS = curve.p
GROUP_GENERATOR = 5


@dataclass
class MaskedIdentity:
    p_id: bytes
    index_id: int
    p_pk: bytes
    index_pk: int

    def encode_for_hash(self) -> bytes:
        return b"".join(
            [
                _encode_length(self.p_id),
                struct.pack(">I", self.index_id),
                _encode_length(self.p_pk),
                struct.pack(">I", self.index_pk),
            ]
        )


@dataclass
class GroupRequest:
    ap_id: str
    ts1: int
    pk_gpi_bytes: bytes
    pk_ap_bytes: bytes
    v_gpi: int


@dataclass
class GroupCredential:
    target_apgid: str
    sgk_bytes: bytes
    expiry_ts: int

    def encode_for_signature(self) -> bytes:
        return b"".join(
            [
                _encode_length(self.target_apgid.encode("utf-8")),
                _encode_length(self.sgk_bytes),
                struct.pack(">Q", self.expiry_ts if self.expiry_ts >= 0 else 0),
            ]
        )


@dataclass
class GroupResponse:
    apgid: str
    hac: List[GroupCredential]
    coefficients: List[int]
    ts1_gm: int
    pk_g_bytes: bytes
    gm_id: str
    pkgm_bytes: bytes
    v_gm: int


@dataclass
class PendingGroupRequest:
    sk_gpi: int
    ts1: int
    pk_gpi_bytes: bytes


@dataclass
class GroupAssignment:
    apgid: str
    apgk_int: int
    coefficients: List[int]
    pk_g_bytes: bytes
    pkgm_bytes: bytes
    gm_id: str
    hac: List[GroupCredential]

    @property
    def apgk_bytes(self) -> bytes:
        size = (GROUP_MODULUS.bit_length() + 7) // 8
        return self.apgk_int.to_bytes(size, "big")

    @property
    def sgk_bytes(self) -> bytes:
        return kdf(self.apgk_bytes, b"Liu2022/sgk")


@dataclass
class GMGroupRecord:
    ap_id: str
    apgid: str
    sk_g_scalar: int
    pk_g_bytes: bytes
    apgk_int: int
    coefficients: List[int]
    expiry_ts: int

    @property
    def apgk_bytes(self) -> bytes:
        size = (GROUP_MODULUS.bit_length() + 7) // 8
        return self.apgk_int.to_bytes(size, "big")

    @property
    def sgk_bytes(self) -> bytes:
        return kdf(self.apgk_bytes, b"Liu2022/sgk")


@dataclass
class AccessRequest:
    identity: MaskedIdentity
    ts1: int
    pk_ue_ep_bytes: bytes
    v_ue: int


@dataclass
class LKATicket:
    apgid: str
    encrypted_payload: bytes
    nonce: bytes
    expiry_ts: int

    def encode_for_hash(self) -> bytes:
        return b"".join(
            [
                _encode_length(self.apgid.encode("utf-8")),
                _encode_length(self.nonce),
                _encode_length(self.encrypted_payload),
                struct.pack(">Q", self.expiry_ts if self.expiry_ts >= 0 else 0),
            ]
        )


def encode_lka_list(tickets: Sequence[LKATicket]) -> bytes:
    return _encode_length(b"".join(ticket.encode_for_hash() for ticket in tickets))


@dataclass
class AccessResponse:
    ciphertext: bytes
    nonce: bytes
    lka: List[LKATicket]
    ts2: int
    pk_ap_ep_bytes: bytes
    ap_id: str
    pk_ap_bytes: bytes
    v_ap: int


@dataclass
class PendingAccessSession:
    sk_ue_ep: int
    ts1: int
    target_ap_id: Optional[str] = None
    target_pk_bytes: Optional[bytes] = None


@dataclass
class ActiveSession:
    ue_id: str
    session_key: bytes
    masked_identity: MaskedIdentity
    lka: List[LKATicket]
    apgid: str


@dataclass
class PendingHandover:
    ru: bytes
    ts1: int
    target_ap_id: str


@dataclass
class HandoverRequest:
    p_id: bytes
    index_id: int
    ru: bytes
    ts1: int
    target_ap_id: str
    lka: List[LKATicket]
    v_ue: bytes


@dataclass
class HandoverResponse:
    r_ap: bytes
    ts2: int
    ciphertext: bytes
    nonce: bytes
    ap_id: str
    v_ap: bytes
    lka: List[LKATicket] = field(default_factory=list)


###############################################################################
# NCC, GM, AP, and UE state definitions
###############################################################################


@dataclass
class UERegistration:
    ue_id: str
    pk_bytes: bytes
    sk_scalar: int
    rt: int


@dataclass
class NCCState:
    sk_scalar: int = field(default_factory=random_scalar)
    pk_bytes: bytes = field(init=False)
    blind_factors: Dict[int, bytes] = field(default_factory=dict)
    next_blind_index: int = 1
    ap_records: Dict[str, Tuple[bytes, int]] = field(default_factory=dict)
    gm_records: Dict[str, Tuple[bytes, int]] = field(default_factory=dict)
    ue_records: Dict[str, UERegistration] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.pk_bytes = point_to_bytes(self.sk_scalar * generator())

    def public_point(self) -> ECp:
        return point_from_bytes(self.pk_bytes)

    def allocate_blind_factor(self, length: int) -> Tuple[int, bytes]:
        index = self.next_blind_index
        self.next_blind_index += 1
        value = os.urandom(length)
        self.blind_factors[index] = value
        return index, value

    def get_blind_factor(self, index: int) -> bytes:
        return self.blind_factors[index]

    def register_ap(self, ap_id: str) -> "APState":
        q_ap = random_scalar()
        pk_ap_point = q_ap * generator()
        pk_ap_bytes = point_to_bytes(pk_ap_point)
        h_value = hash_h2(ap_id, pk_ap_bytes)
        sk_ap = normalize_scalar(q_ap + h_value * self.sk_scalar)
        self.ap_records[ap_id] = (pk_ap_bytes, sk_ap)
        return APState(
            ncc=self,
            ap_id=ap_id,
            q_scalar=q_ap,
            sk_scalar=sk_ap,
            pk_bytes=pk_ap_bytes,
        )

    def register_gm(self, gm_id: str) -> "GMState":
        q_gm = random_scalar()
        pk_gm_point = q_gm * generator()
        pk_gm_bytes = point_to_bytes(pk_gm_point)
        h_value = hash_h2(gm_id, pk_gm_bytes)
        sk_gm = normalize_scalar(q_gm + h_value * self.sk_scalar)
        self.gm_records[gm_id] = (pk_gm_bytes, sk_gm)
        return GMState(
            ncc=self,
            gm_id=gm_id,
            q_scalar=q_gm,
            sk_scalar=sk_gm,
            pk_bytes=pk_gm_bytes,
        )

    def register_ue(self, ue_id: str, *, validity_seconds: int = 3600) -> "UEState":
        q_ue = random_scalar()
        pk_point = q_ue * generator()
        pk_bytes = point_to_bytes(pk_point)
        rt_ue = int(time.time()) + validity_seconds
        h_value = hash_h2(ue_id, pk_bytes, rt_ue.to_bytes(8, "big"))
        sk_ue = normalize_scalar(q_ue + h_value * self.sk_scalar)

        id_bytes = encode_identity_bytes(ue_id)
        idx_id, blind_id = self.allocate_blind_factor(len(id_bytes))
        p_id = xor_bytes(id_bytes, blind_id)

        idx_pk, blind_pk = self.allocate_blind_factor(len(pk_bytes))
        p_pk = xor_bytes(pk_bytes, blind_pk)

        self.ue_records[ue_id] = UERegistration(
            ue_id=ue_id,
            pk_bytes=pk_bytes,
            sk_scalar=sk_ue,
            rt=rt_ue,
        )
        ed = scalar_to_bytes(sk_ue)

        return UEState(
            ue_id=ue_id,
            pk_bytes=pk_bytes,
            sk_scalar=sk_ue,
            validity=rt_ue,
            pk_ncc_bytes=self.pk_bytes,
            masked_identity=MaskedIdentity(
                p_id=p_id,
                index_id=idx_id,
                p_pk=p_pk,
                index_pk=idx_pk,
            ),
            encrypted_secret=ed,
        )

    def get_ue_record(self, ue_id: str) -> UERegistration:
        return self.ue_records[ue_id]


@dataclass
class GMState:
    ncc: NCCState
    gm_id: str
    q_scalar: int
    sk_scalar: int
    pk_bytes: bytes
    ap_groups: Dict[str, GMGroupRecord] = field(default_factory=dict)

    def public_point(self) -> ECp:
        return point_from_bytes(self.pk_bytes)

    def process_group_request(
        self,
        message: GroupRequest,
        now: int,
        *,
        tolerance_ms: int = 1000,
        validity_ms: int = 10 * 60 * 1000,
    ) -> GroupResponse:
        if abs(now - message.ts1) > tolerance_ms:
            raise ValueError("group request timestamp outside tolerance")

        if message.ap_id not in self.ncc.ap_records:
            raise ValueError(f"unknown AP id {message.ap_id}")
        registered_pk, _ = self.ncc.ap_records[message.ap_id]
        if registered_pk != message.pk_ap_bytes:
            raise ValueError("AP public key mismatch at GM")

        pk_gpi_point = point_from_bytes(message.pk_gpi_bytes)
        pk_ap_point = point_from_bytes(message.pk_ap_bytes)
        pk_ncc_point = self.ncc.public_point()

        h_ts_pk_gpi = hash_h2(message.ts1, message.pk_gpi_bytes)
        h_id_ap = hash_h2(message.ap_id, message.pk_ap_bytes)

        lhs_point = normalize_scalar(message.v_gpi) * generator()
        rhs_point = pk_gpi_point.copy()
        rhs_point.add(h_ts_pk_gpi * pk_ap_point)
        rhs_point.add((h_ts_pk_gpi * h_id_ap) * pk_ncc_point)

        if point_to_bytes(lhs_point) != point_to_bytes(rhs_point):
            raise ValueError("group request signature invalid")

        existing_record = self.ap_groups.get(message.ap_id)
        if existing_record is not None:
            print("[DEBUG] GM reuse record for", message.ap_id, "apgk_int", existing_record.apgk_int)
            sk_g = existing_record.sk_g_scalar
            pk_g_bytes = existing_record.pk_g_bytes
            pk_g_point = point_from_bytes(pk_g_bytes)
        else:
            print("[DEBUG] GM create new record for", message.ap_id)
            sk_g = random_scalar()
            pk_g_point = sk_g * generator()
            pk_g_bytes = point_to_bytes(pk_g_point)
        shared_point = sk_g * pk_gpi_point
        shared_x, shared_y = shared_point.get()
        X_i = shared_x % GROUP_MODULUS
        Y_i = pow(GROUP_GENERATOR, shared_y % GROUP_MODULUS, GROUP_MODULUS)
        if Y_i == 0:
            raise ValueError("derived group element has zero Y component")

        if existing_record is not None:
            apgid = existing_record.apgid
            apgk_int = existing_record.apgk_int
        else:
            apgid = f"{self.gm_id}-{message.ap_id}-{len(self.ap_groups) + 1:03d}"
            size_bytes = (GROUP_MODULUS.bit_length() + 7) // 8
            while True:
                apgk_int = int.from_bytes(os.urandom(size_bytes), "big") % GROUP_MODULUS
                if apgk_int != 0:
                    break
        coefficient = (apgk_int * Y_i) % GROUP_MODULUS
        coefficients = [coefficient]

        ts1_gm = now
        expiry_ts = now + validity_ms

        hac_entries: List[GroupCredential] = []
        for record in self.ap_groups.values():
            expiry_value = max(record.expiry_ts, expiry_ts)
            hac_entries.append(
                GroupCredential(
                    target_apgid=record.apgid,
                    sgk_bytes=record.sgk_bytes,
                    expiry_ts=expiry_value,
                )
            )

        challenge = hash_h2(
            apgid,
            encode_hac(hac_entries),
            encode_coefficients(coefficients),
            timestamp_to_bytes(ts1_gm),
            pk_g_bytes,
        )
        v_gm = normalize_scalar(sk_g + challenge * self.sk_scalar)

        record = GMGroupRecord(
            ap_id=message.ap_id,
            apgid=apgid,
            sk_g_scalar=sk_g,
            pk_g_bytes=pk_g_bytes,
            apgk_int=apgk_int,
            coefficients=coefficients,
            expiry_ts=expiry_ts,
        )
        self.ap_groups[message.ap_id] = record
        print("[DEBUG] GM stored record", message.ap_id, "apgk_int", record.apgk_int)

        response = GroupResponse(
            apgid=apgid,
            hac=hac_entries,
            coefficients=coefficients,
            ts1_gm=ts1_gm,
            pk_g_bytes=pk_g_bytes,
            gm_id=self.gm_id,
            pkgm_bytes=self.pk_bytes,
            v_gm=v_gm,
        )
        return response


@dataclass
class APState:
    ncc: NCCState
    ap_id: str
    q_scalar: int
    sk_scalar: int
    pk_bytes: bytes
    pending_group: Optional[PendingGroupRequest] = None
    assignments: Dict[str, GroupAssignment] = field(default_factory=dict)
    current_apgid: Optional[str] = None
    sessions: Dict[str, ActiveSession] = field(default_factory=dict)

    def public_point(self) -> ECp:
        return point_from_bytes(self.pk_bytes)

    def start_group_request(self, ts1: int) -> GroupRequest:
        sk_gpi = random_scalar()
        pk_gpi_point = sk_gpi * generator()
        pk_gpi_bytes = point_to_bytes(pk_gpi_point)
        challenge = hash_h2(ts1, pk_gpi_bytes)
        v_gpi = normalize_scalar(sk_gpi + challenge * self.sk_scalar)
        self.pending_group = PendingGroupRequest(
            sk_gpi=sk_gpi,
            ts1=ts1,
            pk_gpi_bytes=pk_gpi_bytes,
        )
        return GroupRequest(
            ap_id=self.ap_id,
            ts1=ts1,
            pk_gpi_bytes=pk_gpi_bytes,
            pk_ap_bytes=self.pk_bytes,
            v_gpi=v_gpi,
        )

    def process_group_response(
        self,
        response: GroupResponse,
        now: int,
        *,
        tolerance_ms: int = 1000,
    ) -> GroupAssignment:
        if self.pending_group is None:
            raise ValueError("no outstanding group request")
        if abs(now - response.ts1_gm) > tolerance_ms:
            raise ValueError("group response timestamp outside tolerance")

        challenge = hash_h2(
            response.apgid,
            encode_hac(response.hac),
            encode_coefficients(response.coefficients),
            timestamp_to_bytes(response.ts1_gm),
            response.pk_g_bytes,
        )

        lhs_point = normalize_scalar(response.v_gm) * generator()
        pkgm_point = point_from_bytes(response.pkgm_bytes)
        pk_ncc_point = self.ncc.public_point()
        h_gm = hash_h2(response.gm_id, response.pkgm_bytes)

        pk_g_point = point_from_bytes(response.pk_g_bytes)
        rhs_point = pk_g_point.copy()
        rhs_point.add(challenge * pkgm_point)
        rhs_point.add((challenge * h_gm) * pk_ncc_point)

        if point_to_bytes(lhs_point) != point_to_bytes(rhs_point):
            raise ValueError("group response signature invalid")

        shared_point = self.pending_group.sk_gpi * pk_g_point
        shared_x, shared_y = shared_point.get()
        X_prime = shared_x % GROUP_MODULUS
        Y_prime = pow(GROUP_GENERATOR, shared_y % GROUP_MODULUS, GROUP_MODULUS)
        if Y_prime == 0:
            raise ValueError("invalid shared point in group response")
        polynomial_value = evaluate_polynomial(response.coefficients, X_prime, GROUP_MODULUS)
        apgk_int = (polynomial_value * modulus_inverse(Y_prime, GROUP_MODULUS)) % GROUP_MODULUS

        hac_copy = [
            GroupCredential(entry.target_apgid, entry.sgk_bytes, entry.expiry_ts) for entry in response.hac
        ]
        assignment = GroupAssignment(
            apgid=response.apgid,
            apgk_int=apgk_int,
            coefficients=list(response.coefficients),
            pk_g_bytes=response.pk_g_bytes,
            pkgm_bytes=response.pkgm_bytes,
            gm_id=response.gm_id,
            hac=hac_copy,
        )
        self.assignments[response.apgid] = assignment
        self.current_apgid = response.apgid
        self.pending_group = None
        return assignment

    def handle_access_request(
        self,
        request: AccessRequest,
        now: int,
        *,
        tolerance_ms: int = 1000,
    ) -> AccessResponse:
        if abs(now - request.ts1) > tolerance_ms:
            raise ValueError("access request timestamp outside tolerance")
        if self.current_apgid is None or self.current_apgid not in self.assignments:
            raise ValueError("AP has no active group assignment")

        blind_id = self.ncc.get_blind_factor(request.identity.index_id)
        blind_pk = self.ncc.get_blind_factor(request.identity.index_pk)
        id_bytes = xor_bytes(request.identity.p_id, blind_id)
        pk_bytes = xor_bytes(request.identity.p_pk, blind_pk)
        ue_id = decode_identity_bytes(id_bytes)

        ue_record = self.ncc.get_ue_record(ue_id)
        if ue_record.pk_bytes != pk_bytes:
            raise ValueError("UE public key mismatch at AP")

        rt_bytes = ue_record.rt.to_bytes(8, "big")
        challenge = hash_h2(
            request.identity.encode_for_hash(),
            timestamp_to_bytes(request.ts1),
            request.pk_ue_ep_bytes,
        )
        h_rt = hash_h2(ue_id, pk_bytes, rt_bytes)

        lhs_point = normalize_scalar(request.v_ue) * generator()
        pk_ue_ep_point = point_from_bytes(request.pk_ue_ep_bytes)
        pk_ue_point = point_from_bytes(pk_bytes)
        pk_ncc_point = self.ncc.public_point()

        rhs_point = pk_ue_ep_point.copy()
        rhs_point.add(challenge * pk_ue_point)
        rhs_point.add((challenge * h_rt) * pk_ncc_point)

        if point_to_bytes(lhs_point) != point_to_bytes(rhs_point):
            raise ValueError("access request verification failed")

        assignment = self.assignments[self.current_apgid]

        sk_ap_ep = random_scalar()
        pk_ap_ep_point = sk_ap_ep * generator()
        pk_ap_ep_bytes = point_to_bytes(pk_ap_ep_point)
        shared_point = sk_ap_ep * pk_ue_ep_point
        shared_bytes = point_to_bytes(shared_point)
        session_key = derive_session_key(shared_bytes)

        idx_id_new, blind_id_new = self.ncc.allocate_blind_factor(len(id_bytes))
        p_id_new = xor_bytes(id_bytes, blind_id_new)
        idx_pk_new, blind_pk_new = self.ncc.allocate_blind_factor(len(pk_bytes))
        p_pk_new = xor_bytes(pk_bytes, blind_pk_new)
        new_identity = MaskedIdentity(p_id_new, idx_id_new, p_pk_new, idx_pk_new)

        identity_payload = pack_identity_update(new_identity)
        nonce, ciphertext = encrypt_with_key(session_key, identity_payload)

        lka_tickets: List[LKATicket] = []
        for credential in assignment.hac:
            payload = pack_lka_payload(session_key, ue_id, credential.expiry_ts)
            ticket_nonce, ticket_cipher = encrypt_with_key(credential.sgk_bytes, payload)
            lka_tickets.append(
                LKATicket(
                    apgid=credential.target_apgid,
                    encrypted_payload=ticket_cipher,
                    nonce=ticket_nonce,
                    expiry_ts=credential.expiry_ts,
                )
            )

        ts2 = now
        challenge_ap = hash_h2(
            ciphertext,
            encode_lka_list(lka_tickets),
            timestamp_to_bytes(ts2),
            pk_ap_ep_bytes,
        )
        v_ap = normalize_scalar(sk_ap_ep + challenge_ap * self.sk_scalar)

        self.sessions[ue_id] = ActiveSession(
            ue_id=ue_id,
            session_key=session_key,
            masked_identity=new_identity,
            lka=lka_tickets,
            apgid=assignment.apgid,
        )

        return AccessResponse(
            ciphertext=ciphertext,
            nonce=nonce,
            lka=lka_tickets,
            ts2=ts2,
            pk_ap_ep_bytes=pk_ap_ep_bytes,
            ap_id=self.ap_id,
            pk_ap_bytes=self.pk_bytes,
            v_ap=v_ap,
        )

    def process_handover_request(
        self,
        request: HandoverRequest,
        now: int,
        *,
        tolerance_ms: int = 1000,
    ) -> HandoverResponse:
        if abs(now - request.ts1) > tolerance_ms:
            raise ValueError("handover request timestamp outside tolerance")
        if self.current_apgid is None or self.current_apgid not in self.assignments:
            raise ValueError("AP has no active group assignment")

        assignment = self.assignments[self.current_apgid]

        blind_id = self.ncc.get_blind_factor(request.index_id)
        id_bytes = xor_bytes(request.p_id, blind_id)
        ue_id = decode_identity_bytes(id_bytes)

        matching_ticket = None
        for ticket in request.lka:
            if ticket.apgid == assignment.apgid:
                matching_ticket = ticket
                break
        if matching_ticket is None:
            for ticket in request.lka:
                alt_assignment = self.assignments.get(ticket.apgid)
                if alt_assignment is not None:
                    assignment = alt_assignment
                    matching_ticket = ticket
                    break
        if matching_ticket is None:
            raise ValueError("no matching LKA entry for this AP")
        if now > matching_ticket.expiry_ts:
            raise ValueError("LKA entry expired")

        payload = decrypt_with_key(
            assignment.sgk_bytes,
            matching_ticket.nonce,
            matching_ticket.encrypted_payload,
        )
        sk_old, ue_check, expiry_ts = unpack_lka_payload(payload)
        if ue_check != ue_id:
            raise ValueError("LKA payload UE mismatch")
        if now > expiry_ts:
            raise ValueError("LKA payload expired")

        expected_v = hash_h1(
            sk_old,
            request.p_id,
            struct.pack(">I", request.index_id),
            request.ru,
            timestamp_to_bytes(request.ts1),
            request.target_ap_id,
            encode_lka_list(request.lka),
        )
        if expected_v != request.v_ue:
            raise ValueError("handover request verification failed")

        r_ap = os.urandom(16)
        ts2 = now
        sk_new = kdf(sk_old, r_ap, request.ru, self.ap_id, ue_id)

        idx_new, blind_new = self.ncc.allocate_blind_factor(len(id_bytes))
        p_id_new = xor_bytes(id_bytes, blind_new)
        identity_payload = pack_handover_identity(p_id_new, idx_new)
        nonce, ciphertext = encrypt_with_key(sk_new, identity_payload)

        lka_tickets: List[LKATicket] = []
        for credential in assignment.hac:
            payload = pack_lka_payload(sk_new, ue_id, credential.expiry_ts)
            ticket_nonce, ticket_cipher = encrypt_with_key(credential.sgk_bytes, payload)
            lka_tickets.append(
                LKATicket(
                    apgid=credential.target_apgid,
                    encrypted_payload=ticket_cipher,
                    nonce=ticket_nonce,
                    expiry_ts=credential.expiry_ts,
                )
            )

        v_ap = hash_h1(
            sk_old,
            r_ap,
            timestamp_to_bytes(ts2),
            ciphertext,
            self.ap_id,
        )

        self.sessions[ue_id] = ActiveSession(
            ue_id=ue_id,
            session_key=sk_new,
            masked_identity=MaskedIdentity(
                p_id=p_id_new,
                index_id=idx_new,
                p_pk=b"",
                index_pk=0,
            ),
            lka=lka_tickets,
            apgid=assignment.apgid,
        )

        return HandoverResponse(
            r_ap=r_ap,
            ts2=ts2,
            ciphertext=ciphertext,
            nonce=nonce,
            ap_id=self.ap_id,
            v_ap=v_ap,
            lka=lka_tickets,
        )


@dataclass
class UEState:
    ue_id: str
    pk_bytes: bytes
    sk_scalar: int
    validity: int
    pk_ncc_bytes: bytes
    masked_identity: MaskedIdentity
    encrypted_secret: bytes
    pending_access: Optional[PendingAccessSession] = None
    pending_handover: Optional[PendingHandover] = None
    session_key: Optional[bytes] = None
    lka: List[LKATicket] = field(default_factory=list)

    def create_access_request(
        self,
        ts1: int,
    ) -> AccessRequest:
        sk_ue_ep = random_scalar()
        pk_ue_ep_point = sk_ue_ep * generator()
        pk_ue_ep_bytes = point_to_bytes(pk_ue_ep_point)
        challenge = hash_h2(
            self.masked_identity.encode_for_hash(),
            timestamp_to_bytes(ts1),
            pk_ue_ep_bytes,
        )
        v_ue = normalize_scalar(sk_ue_ep + challenge * self.sk_scalar)
        self.pending_access = PendingAccessSession(
            sk_ue_ep=sk_ue_ep,
            ts1=ts1,
        )
        return AccessRequest(
            identity=self.masked_identity,
            ts1=ts1,
            pk_ue_ep_bytes=pk_ue_ep_bytes,
            v_ue=v_ue,
        )

    def process_access_response(
        self,
        response: AccessResponse,
        now: int,
        *,
        tolerance_ms: int = 1000,
    ) -> ActiveSession:
        if self.pending_access is None:
            raise ValueError("no pending access session")
        if abs(now - response.ts2) > tolerance_ms:
            raise ValueError("access response timestamp outside tolerance")

        challenge = hash_h2(
            response.ciphertext,
            encode_lka_list(response.lka),
            timestamp_to_bytes(response.ts2),
            response.pk_ap_ep_bytes,
        )

        lhs_point = normalize_scalar(response.v_ap) * generator()
        pk_ap_ep_point = point_from_bytes(response.pk_ap_ep_bytes)
        pk_ap_point = point_from_bytes(response.pk_ap_bytes)
        pk_ncc_point = point_from_bytes(self.pk_ncc_bytes)
        h_ap = hash_h2(response.ap_id, response.pk_ap_bytes)

        rhs_point = pk_ap_ep_point.copy()
        rhs_point.add(challenge * pk_ap_point)
        rhs_point.add((challenge * h_ap) * pk_ncc_point)

        if point_to_bytes(lhs_point) != point_to_bytes(rhs_point):
            raise ValueError("access response verification failed")

        shared_point = self.pending_access.sk_ue_ep * pk_ap_ep_point
        shared_bytes = point_to_bytes(shared_point)
        session_key = derive_session_key(shared_bytes)

        plaintext = decrypt_with_key(session_key, response.nonce, response.ciphertext)
        new_identity = unpack_identity_update(plaintext)
        self.masked_identity = new_identity
        self.session_key = session_key
        self.lka = response.lka
        self.pending_access = None

        apgid = response.lka[0].apgid if response.lka else ""
        return ActiveSession(
            ue_id=self.ue_id,
            session_key=session_key,
            masked_identity=new_identity,
            lka=response.lka,
            apgid=apgid,
        )

    def create_handover_request(
        self,
        target_ap_id: str,
        ts1: int,
    ) -> HandoverRequest:
        if self.session_key is None:
            raise ValueError("no active session to handover")
        ru = os.urandom(16)
        v_ue = hash_h1(
            self.session_key,
            self.masked_identity.p_id,
            struct.pack(">I", self.masked_identity.index_id),
            ru,
            timestamp_to_bytes(ts1),
            target_ap_id,
            encode_lka_list(self.lka),
        )
        self.pending_handover = PendingHandover(
            ru=ru,
            ts1=ts1,
            target_ap_id=target_ap_id,
        )
        return HandoverRequest(
            p_id=self.masked_identity.p_id,
            index_id=self.masked_identity.index_id,
            ru=ru,
            ts1=ts1,
            target_ap_id=target_ap_id,
            lka=self.lka,
            v_ue=v_ue,
        )

    def process_handover_response(
        self,
        response: HandoverResponse,
        now: int,
        *,
        tolerance_ms: int = 1000,
    ) -> None:
        if self.session_key is None or self.pending_handover is None:
            raise ValueError("no pending handover")
        if abs(now - response.ts2) > tolerance_ms:
            raise ValueError("handover response timestamp outside tolerance")

        expected = hash_h1(
            self.session_key,
            response.r_ap,
            timestamp_to_bytes(response.ts2),
            response.ciphertext,
            response.ap_id,
        )
        if expected != response.v_ap:
            raise ValueError("handover response verification failed")

        sk_new = kdf(
            self.session_key,
            response.r_ap,
            self.pending_handover.ru,
            response.ap_id,
            self.ue_id,
        )
        plaintext = decrypt_with_key(sk_new, response.nonce, response.ciphertext)
        p_id_new, index_new = unpack_handover_identity(plaintext)
        self.masked_identity = MaskedIdentity(
            p_id=p_id_new,
            index_id=index_new,
            p_pk=self.masked_identity.p_pk,
            index_pk=self.masked_identity.index_pk,
        )
        self.session_key = sk_new
        self.lka = list(response.lka)
        self.pending_handover = None


###############################################################################
# Convenience helpers to drive end-to-end flows
###############################################################################


__all__ = [
    "NCCState",
    "GMState",
    "APState",
    "UEState",
    "GroupRequest",
    "GroupResponse",
    "AccessRequest",
    "AccessResponse",
    "HandoverRequest",
    "HandoverResponse",
    "MaskedIdentity",
    "LKATicket",
    "GroupCredential",
    "GroupAssignment",
    "ActiveSession",
]
