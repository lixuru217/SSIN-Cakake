#!/usr/bin/env python3
"""
SSINAuth protocol implementation built on top of MIRACL Core primitives.

This module models the five phases described in the specification:
1. System initialisation (domain KGC setup)
2. Registration for every entity (UE, helper S_A, authenticator S_B)
3. Pre-authentication relay via helper
4. Public-channel mutual authentication and session key derivation
5. Batch verification handled by the authenticator

The focus is to keep the elliptic-curve operations explicit while keeping the
message flow close to the textual description.  Symmetric channels are modelled
as trusted envelopes which simply label the channel in which the message
travels – replacing the underlying encryption which is assumed to exist.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from miracl_aes import EncryptedPayload, MiraclCTRChannel

from bn254 import big
from bn254 import curve
from bn254.ecp import ECp, generator

################################################################################
# Hash helpers with explicit domain separation
################################################################################


def _encode_length(data: bytes) -> bytes:
    """Prefix each byte string with its length to avoid collisions."""
    return struct.pack(">I", len(data)) + data


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


def hash_identity(entity_id: str, domain_id: str) -> Tuple[str, bytes]:
    """
    Produce a canonical identity string and its fixed-size byte representation.

    All XOR operations use this fixed-length representation, while the string
    (``entity_id@domain_id``) is kept for logging and domain lookups.
    """
    canonical = f"{entity_id}@{domain_id}"
    return canonical, hashlib.sha256(canonical.encode("utf-8")).digest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def timestamp_to_bytes(ts: int) -> bytes:
    return ts.to_bytes(12, "big", signed=False)


################################################################################
# EC helpers
################################################################################


def random_scalar() -> int:
    """Return a fresh random scalar in [2, r-1]."""
    return big.rand(curve.r)


def scalar_to_bytes(k: int) -> bytes:
    return k.to_bytes(curve.EFS, "big")


def point_to_bytes(P: ECp) -> bytes:
    return P.toBytes(False)


def point_from_bytes(data: bytes) -> ECp:
    P = ECp()
    if not P.fromBytes(data):
        raise ValueError("invalid point encoding")
    return P


def scalar_mul_point(scalar: int, point_bytes: bytes) -> ECp:
    return scalar * point_from_bytes(point_bytes)


def add_points(points: Iterable[ECp]) -> ECp:
    acc: Optional[ECp] = None
    for P in points:
        if acc is None:
            acc = P.copy()
        else:
            acc.add(P)
    if acc is None:
        raise ValueError("no points supplied")
    return acc


################################################################################
# Secure-channel abstraction
################################################################################


def _encode_payload(payload: Dict[str, bytes]) -> bytes:
    items = sorted(payload.items())
    buf = bytearray()
    buf.extend(len(items).to_bytes(2, "big"))
    for key, value in items:
        key_bytes = key.encode("utf-8")
        buf.extend(len(key_bytes).to_bytes(2, "big"))
        buf.extend(key_bytes)
        buf.extend(len(value).to_bytes(4, "big"))
        buf.extend(value)
    return bytes(buf)


def _decode_payload(encoded: bytes) -> Dict[str, bytes]:
    view = memoryview(encoded)
    offset = 0
    if len(view) < 2:
        raise ValueError("encoded payload too short")
    items = int.from_bytes(view[offset : offset + 2], "big")
    offset += 2
    result: Dict[str, bytes] = {}
    for _ in range(items):
        if offset + 2 > len(view):
            raise ValueError("truncated key length")
        key_len = int.from_bytes(view[offset : offset + 2], "big")
        offset += 2
        if offset + key_len > len(view):
            raise ValueError("truncated key")
        key = view[offset : offset + key_len].tobytes().decode("utf-8")
        offset += key_len
        if offset + 4 > len(view):
            raise ValueError("truncated value length")
        value_len = int.from_bytes(view[offset : offset + 4], "big")
        offset += 4
        if offset + value_len > len(view):
            raise ValueError("truncated value")
        value = view[offset : offset + value_len].tobytes()
        offset += value_len
        result[key] = value
    if offset != len(view):
        raise ValueError("unexpected trailing data in payload")
    return result


@dataclass
class SecureEnvelope:
    channel_label: str
    nonce: bytes
    ciphertext: bytes


@dataclass
class SecureChannel:
    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) not in (16, 24, 32):
            raise ValueError("secure channel key must be 16/24/32 bytes")
        self.label = hashlib.sha256(self.key).hexdigest()[:16]
        self.cipher = MiraclCTRChannel(self.key)

    def encrypt(self, payload: Dict[str, bytes]) -> SecureEnvelope:
        encoded = _encode_payload(payload)
        encrypted = self.cipher.encrypt(encoded)
        return SecureEnvelope(self.label, encrypted.nonce, encrypted.ciphertext)

    def decrypt(self, envelope: SecureEnvelope) -> Dict[str, bytes]:
        if envelope.channel_label != self.label:
            raise ValueError("wrong secure channel")
        plaintext = self.cipher.decrypt(EncryptedPayload(envelope.nonce, envelope.ciphertext))
        return _decode_payload(plaintext)


def establish_secure_channel(a: "EntityState", b: "EntityState") -> SecureChannel:
    shared_point = a.x * point_from_bytes(b.P_bytes)
    shared_bytes = point_to_bytes(shared_point)
    ids = sorted([a.canonical_id, b.canonical_id])
    key_material = hash_to_bytes(b"Hchan", shared_bytes, ids[0].encode("utf-8"), ids[1].encode("utf-8"))
    return SecureChannel(key_material[:16])


################################################################################
# Domain KGC and entity representation
################################################################################


@dataclass
class DomainPublicRecord:
    entity_id: str
    domain_id: str
    identity_bytes: bytes
    h: int
    pk_bytes: bytes
    P_bytes: bytes


@dataclass
class DomainKGC:
    domain_id: str
    master_secret: int = field(default_factory=random_scalar)
    registry: Dict[str, DomainPublicRecord] = field(default_factory=dict)
    identity_map: Dict[bytes, Tuple[str, str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        G = generator()
        self.public_point_bytes = point_to_bytes(self.master_secret * G)

    def register_entity(self, entity_id: str, P_bytes: bytes) -> Tuple[int, int, bytes, int]:
        """
        Perform steps handled by the KGC during registration.

        Returns the tuple (sk_i, r_i, pk_i_bytes, h_i).
        """
        canonical, identity_bytes = hash_identity(entity_id, self.domain_id)
        self.identity_map[identity_bytes] = (entity_id, self.domain_id)

        r_i = random_scalar()
        pk_point = r_i * generator()
        pk_bytes = point_to_bytes(pk_point)

        h_i = hash_to_scalar(
            b"H1",
            canonical.encode("utf-8"),
            self.domain_id.encode("utf-8"),
            pk_bytes,
            P_bytes,
        )

        sk_i = (r_i + h_i * self.master_secret) % curve.r

        self.registry[entity_id] = DomainPublicRecord(
            entity_id=entity_id,
            domain_id=self.domain_id,
            identity_bytes=identity_bytes,
            h=h_i,
            pk_bytes=pk_bytes,
            P_bytes=P_bytes,
        )
        return sk_i, r_i, pk_bytes, h_i

    def public_record(self, entity_id: str) -> DomainPublicRecord:
        return self.registry[entity_id]

    def resolve_identity(self, identity_bytes: bytes) -> Tuple[str, str]:
        return self.identity_map[identity_bytes]

    def public_point(self) -> bytes:
        return self.public_point_bytes


################################################################################
# Entity state
################################################################################


@dataclass
class EntityState:
    entity_id: str
    domain: DomainKGC
    canonical_id: str
    identity_bytes: bytes
    h: int
    pk_bytes: bytes
    P_bytes: bytes
    x: int
    r: int
    sk_partial: int
    SK: int
    pre_auth_cache: Dict[str, "UEPreAuthCache"] = field(default_factory=dict)
    incoming_sessions: Dict[str, "SBPreAuthCache"] = field(default_factory=dict)
    vrf_sk: Optional[bytes] = None
    vrf_vk: Optional[bytes] = None

    def public_record(self) -> DomainPublicRecord:
        return self.domain.public_record(self.entity_id)


def create_entity(domain: DomainKGC, entity_id: str, *, with_vrf: bool = False) -> EntityState:
    """
    Run the full registration flow for a new entity and return its state.
    """
    canonical, identity_bytes = hash_identity(entity_id, domain.domain_id)
    x_i = random_scalar()
    P_point = x_i * generator()
    P_bytes = point_to_bytes(P_point)

    sk_i, r_i, pk_bytes, h_i = domain.register_entity(entity_id, P_bytes)

    total = (sk_i + x_i) % curve.r
    if total == 0:
        raise ValueError("degenerate key – retry registration")
    SK_i = pow(total, -1, curve.r)

    state = EntityState(
        entity_id=entity_id,
        domain=domain,
        canonical_id=canonical,
        identity_bytes=identity_bytes,
        h=h_i,
        pk_bytes=pk_bytes,
        P_bytes=P_bytes,
        x=x_i,
        r=r_i,
        sk_partial=sk_i,
        SK=SK_i,
    )

    if with_vrf:
        vrf_sk = os.urandom(32)
        vrf_vk = hashlib.sha256(vrf_sk).digest()
        state.vrf_sk = vrf_sk
        state.vrf_vk = vrf_vk

    return state


################################################################################
# Pre-auth caches
################################################################################


@dataclass
class UEPreAuthCache:
    helper_id: str
    target_id: str
    target_domain_id: str
    ue_pid: bytes
    helper_pid: bytes
    helper_identity_bytes: bytes
    m_i: int
    M_i_bytes: bytes
    h_target: int
    pid_target: bytes
    M_target_bytes: bytes
    ts1: int
    ts4: int


@dataclass
class SBPreAuthCache:
    ue_id: str
    ue_domain_id: str
    ue_identity_bytes: bytes
    helper_identity_bytes: bytes
    ue_pid: bytes
    helper_pid: bytes
    h_ue: int
    ue_pk_bytes: bytes
    ue_P_bytes: bytes
    ue_domain_pub: bytes
    M_ue_bytes: bytes
    m_B: int
    M_B_bytes: bytes
    ts2: int
    ts3: int


@dataclass
class UEOfflineRecord:
    state: "EntityState"
    channel: SecureChannel
    pre_auth_cache: UEPreAuthCache


@dataclass
class OfflineContext:
    ue_records: Dict[str, UEOfflineRecord]
    helper: "EntityState"
    authenticator: "EntityState"
    helper_auth_channel: SecureChannel


################################################################################
# Phase 3 – Pre-authentication via helper
################################################################################


def compute_pid(identity_bytes: bytes, M_bytes: bytes) -> bytes:
    return xor_bytes(identity_bytes, hash_to_bytes(b"Hpid", M_bytes))


def pre_authenticate(
    ue: EntityState,
    helper: EntityState,
    authenticator: EntityState,
    channel_ue_sa: SecureChannel,
    channel_sa_sb: SecureChannel,
    ts1: int,
    ts2: int,
    ts3: int,
    ts4: int,
) -> Tuple[List[SecureEnvelope], UEPreAuthCache, SBPreAuthCache]:
    """
    Execute the four-message pre-authentication relay.

    Returns the envelopes exchanged plus the caches needed for the public phase.
    """
    # Step 1 – UE → S_A
    m_i = random_scalar()
    M_i_point = m_i * generator()
    M_i_bytes = point_to_bytes(M_i_point)
    pid_i = compute_pid(ue.identity_bytes, M_i_bytes)

    msg1_payload = {
        "h_i": scalar_to_bytes(ue.h),
        "M_i": M_i_bytes,
        "PID_i": pid_i,
        "TS1": timestamp_to_bytes(ts1),
    }
    envelope1 = channel_ue_sa.encrypt(msg1_payload)

    # Step 2 – S_A → S_B
    pid_a = compute_pid(helper.identity_bytes, M_i_bytes)
    msg2_payload = {
        "h_i": scalar_to_bytes(ue.h),
        "M_i": M_i_bytes,
        "PID_i": pid_i,
        "PID_A": pid_a,
        "TS2": timestamp_to_bytes(ts2),
    }
    envelope2 = channel_sa_sb.encrypt(msg2_payload)

    # Step 3 – S_B → S_A
    identity_bytes_ue = xor_bytes(pid_i, hash_to_bytes(b"Hpid", M_i_bytes))
    if identity_bytes_ue != ue.identity_bytes:
        raise ValueError("unexpected UE identity recovered at authenticator")

    m_B = random_scalar()
    M_B_point = m_B * generator()
    M_B_bytes = point_to_bytes(M_B_point)
    pid_B = compute_pid(authenticator.identity_bytes, M_B_bytes)

    msg3_payload = {
        "h_B": scalar_to_bytes(authenticator.h),
        "M_B": M_B_bytes,
        "PID_A": pid_a,
        "PID_B": pid_B,
        "TS3": timestamp_to_bytes(ts3),
    }
    envelope3 = channel_sa_sb.encrypt(msg3_payload)

    # Step 4 – S_A → UE
    msg4_payload = {
        "h_B": scalar_to_bytes(authenticator.h),
        "M_B": M_B_bytes,
        "PID_A": pid_a,
        "PID_B": pid_B,
        "TS4": timestamp_to_bytes(ts4),
    }
    envelope4 = channel_ue_sa.encrypt(msg4_payload)

    # Build caches
    ue_cache = UEPreAuthCache(
        helper_id=helper.entity_id,
        target_id=authenticator.entity_id,
        target_domain_id=authenticator.domain.domain_id,
        ue_pid=pid_i,
        helper_pid=pid_a,
        helper_identity_bytes=helper.identity_bytes,
        m_i=m_i,
        M_i_bytes=M_i_bytes,
        h_target=authenticator.h,
        pid_target=pid_B,
        M_target_bytes=M_B_bytes,
        ts1=ts1,
        ts4=ts4,
    )

    sb_cache = SBPreAuthCache(
        ue_id=ue.entity_id,
        ue_domain_id=ue.domain.domain_id,
        ue_identity_bytes=identity_bytes_ue,
        helper_identity_bytes=helper.identity_bytes,
        ue_pid=pid_i,
        helper_pid=pid_a,
        h_ue=ue.h,
        ue_pk_bytes=ue.pk_bytes,
        ue_P_bytes=ue.P_bytes,
        ue_domain_pub=ue.domain.public_point(),
        M_ue_bytes=M_i_bytes,
        m_B=m_B,
        M_B_bytes=M_B_bytes,
        ts2=ts2,
        ts3=ts3,
    )

    ue.pre_auth_cache[authenticator.entity_id] = ue_cache
    authenticator.incoming_sessions[ue.entity_id] = sb_cache

    return [envelope1, envelope2, envelope3, envelope4], ue_cache, sb_cache


def perform_offline_phase(
    ue_ids: Sequence[str],
    *,
    ue_domain_id: str = "D_UE",
    sat_domain_id: str = "D_SAT",
    helper_id: str = "leo-helper",
    authenticator_id: str = "leo-target",
    base_timestamp: int = 1,
) -> OfflineContext:
    """
    Execute the registration and pre-authentication stages for all parties.
    """
    domains = initialise_domains({ue_domain_id, sat_domain_id})
    helper = create_entity(domains[sat_domain_id], helper_id)
    authenticator = create_entity(domains[sat_domain_id], authenticator_id, with_vrf=True)
    helper_auth_channel = establish_secure_channel(helper, authenticator)

    ue_records: Dict[str, UEOfflineRecord] = {}
    timestamp = max(base_timestamp, 1)

    for identifier in ue_ids:
        ue_state = create_entity(domains[ue_domain_id], identifier)
        ue_channel = establish_secure_channel(ue_state, helper)
        envelopes, ue_cache, _ = pre_authenticate(
            ue_state,
            helper,
            authenticator,
            ue_channel,
            helper_auth_channel,
            ts1=timestamp,
            ts2=timestamp + 1,
            ts3=timestamp + 2,
            ts4=timestamp + 3,
        )
        ue_records[identifier] = UEOfflineRecord(
            state=ue_state,
            channel=ue_channel,
            pre_auth_cache=ue_cache,
        )
        timestamp += 10

    return OfflineContext(
        ue_records=ue_records,
        helper=helper,
        authenticator=authenticator,
        helper_auth_channel=helper_auth_channel,
    )


################################################################################
# Phase 4 – Mutual authentication and key derivation
################################################################################


def _combo_point(h: int, P_pub_bytes: bytes, pk_bytes: bytes, P_bytes: bytes) -> ECp:
    """
    Compute h·P_pub + pk + P_i.
    """
    P_pub = scalar_mul_point(h, P_pub_bytes)
    pk_point = point_from_bytes(pk_bytes)
    P_point = point_from_bytes(P_bytes)
    P_pub.add(pk_point)
    P_pub.add(P_point)
    return P_pub


def _ensure_timestamp_fresh(ts: int, reference: int, tolerance: int) -> None:
    if reference > 0 and abs(reference - ts) > tolerance:
        raise ValueError("stale timestamp detected")


@dataclass
class MutualAuthResult:
    Q_i: bytes
    V1: bytes
    Q_B: bytes
    V2: bytes
    session_key: Optional[bytes]
    shared_point_bytes: bytes
    TS5: int
    TS6: int
    uplink: UplinkRequest


def _get_session_caches(
    ue: EntityState, authenticator: EntityState
) -> Tuple[UEPreAuthCache, SBPreAuthCache]:
    if authenticator.entity_id not in ue.pre_auth_cache:
        raise ValueError("missing pre-auth cache for authenticator")
    if ue.entity_id not in authenticator.incoming_sessions:
        raise ValueError("authenticator missing UE cache from pre-auth")
    return (
        ue.pre_auth_cache[authenticator.entity_id],
        authenticator.incoming_sessions[ue.entity_id],
    )


def prepare_uplink(
    ue: EntityState,
    authenticator: EntityState,
    *,
    ts5: int,
    tolerance: int = 300,
    fresh_reference: int = 0,
) -> UplinkRequest:
    ue_cache, _ = _get_session_caches(ue, authenticator)
    _ensure_timestamp_fresh(ts5, fresh_reference, tolerance)

    Q_i_point = ue_cache.m_i * _combo_point(
        authenticator.h,
        authenticator.domain.public_point(),
        authenticator.pk_bytes,
        authenticator.P_bytes,
    )
    Q_i_bytes = point_to_bytes(Q_i_point)

    V1 = hash_to_bytes(
        b"H2",
        ue.canonical_id.encode("utf-8"),
        authenticator.canonical_id.encode("utf-8"),
        ue_cache.M_i_bytes,
        timestamp_to_bytes(ts5),
    )

    return UplinkRequest(
        ue_canonical=ue.canonical_id,
        Q_bytes=Q_i_bytes,
        V1=V1,
        TS5=ts5,
        M_bytes=ue_cache.M_i_bytes,
    )


def finalize_authentication(
    ue: EntityState,
    authenticator: EntityState,
    uplink: UplinkRequest,
    q_b_bytes: bytes,
    v2_bytes: bytes,
    *,
    ts6: int,
    tolerance: int = 300,
    fresh_reference: int = 0,
    derive_session_key: bool = True,
) -> MutualAuthResult:
    ue_cache, sb_cache = _get_session_caches(ue, authenticator)

    _ensure_timestamp_fresh(uplink.TS5, fresh_reference, tolerance)
    _ensure_timestamp_fresh(ts6, fresh_reference, tolerance)

    M_prime_i = authenticator.SK * point_from_bytes(uplink.Q_bytes)
    if point_to_bytes(M_prime_i) != ue_cache.M_i_bytes:
        raise ValueError("UE challenge invalid")

    expected_V1 = hash_to_bytes(
        b"H2",
        uplink.ue_canonical.encode("utf-8"),
        authenticator.canonical_id.encode("utf-8"),
        ue_cache.M_i_bytes,
        timestamp_to_bytes(uplink.TS5),
    )
    if uplink.V1 != expected_V1:
        raise ValueError("V1 mismatch")

    combo_B = _combo_point(
        sb_cache.h_ue,
        ue.domain.public_point(),
        ue.pk_bytes,
        ue.P_bytes,
    )
    expected_q_b_bytes = point_to_bytes(sb_cache.m_B * combo_B)
    if q_b_bytes != expected_q_b_bytes:
        raise ValueError("Q_B mismatch")

    expected_V2 = hash_to_bytes(
        b"H2",
        uplink.ue_canonical.encode("utf-8"),
        authenticator.canonical_id.encode("utf-8"),
        ue_cache.M_i_bytes,
        sb_cache.M_B_bytes,
        timestamp_to_bytes(ts6),
    )
    if v2_bytes != expected_V2:
        raise ValueError("V2 mismatch")

    M_prime_B = ue.SK * point_from_bytes(q_b_bytes)
    if point_to_bytes(M_prime_B) != sb_cache.M_B_bytes:
        raise ValueError("Authenticator response invalid")

    shared_point = ue_cache.m_i * point_from_bytes(sb_cache.M_B_bytes)
    shared_point_bytes = point_to_bytes(shared_point)

    session_key: Optional[bytes] = None
    if derive_session_key:
        session_key = hash_to_bytes(
            b"H3",
            shared_point_bytes,
            uplink.ue_canonical.encode("utf-8"),
            ue.domain.domain_id.encode("utf-8"),
            authenticator.canonical_id.encode("utf-8"),
            authenticator.domain.domain_id.encode("utf-8"),
            timestamp_to_bytes(uplink.TS5),
            timestamp_to_bytes(ts6),
        )

        shared_point_sb = sb_cache.m_B * point_from_bytes(ue_cache.M_i_bytes)
        if point_to_bytes(shared_point_sb) != shared_point_bytes:
            raise ValueError("shared secret mismatch between UE and S_B")

        authenticator_session_key = hash_to_bytes(
            b"H3",
            shared_point_bytes,
            uplink.ue_canonical.encode("utf-8"),
            ue.domain.domain_id.encode("utf-8"),
            authenticator.canonical_id.encode("utf-8"),
            authenticator.domain.domain_id.encode("utf-8"),
            timestamp_to_bytes(uplink.TS5),
            timestamp_to_bytes(ts6),
        )
        if authenticator_session_key != session_key:
            raise ValueError("session key derivation diverged")

    return MutualAuthResult(
        Q_i=uplink.Q_bytes,
        V1=uplink.V1,
        Q_B=q_b_bytes,
        V2=v2_bytes,
        session_key=session_key,
        shared_point_bytes=shared_point_bytes,
        TS5=uplink.TS5,
        TS6=ts6,
        uplink=uplink,
    )


def mutual_authentication(
    ue: EntityState,
    authenticator: EntityState,
    *,
    ts5: int,
    ts6: int,
    tolerance: int = 300,
    fresh_reference: int = 0,
) -> MutualAuthResult:
    uplink = prepare_uplink(
        ue,
        authenticator,
        ts5=ts5,
        tolerance=tolerance,
        fresh_reference=fresh_reference,
    )
    q_b_bytes, v2 = authenticator_process_uplink(
        authenticator,
        authenticator.incoming_sessions[ue.entity_id],
        uplink,
        ts6=ts6,
        tolerance=tolerance,
        fresh_reference=fresh_reference,
    )
    return finalize_authentication(
        ue,
        authenticator,
        uplink,
        q_b_bytes,
        v2,
        ts6=ts6,
        tolerance=tolerance,
        fresh_reference=fresh_reference,
    )


def authenticator_process_uplink(
    authenticator: EntityState,
    sb_cache: SBPreAuthCache,
    uplink: UplinkRequest,
    *,
    ts6: int,
    tolerance: int = 300,
    fresh_reference: int = 0,
) -> Tuple[bytes, bytes]:
    """Generate the downlink response for a received uplink request."""
    expected_canonical = f"{sb_cache.ue_id}@{sb_cache.ue_domain_id}"
    if uplink.ue_canonical != expected_canonical:
        raise ValueError("uplink canonical id mismatch")

    _ensure_timestamp_fresh(uplink.TS5, fresh_reference, tolerance)

    M_prime_i = authenticator.SK * point_from_bytes(uplink.Q_bytes)
    if point_to_bytes(M_prime_i) != sb_cache.M_ue_bytes:
        raise ValueError("uplink verification failed")

    expected_V1 = hash_to_bytes(
        b"H2",
        uplink.ue_canonical.encode("utf-8"),
        authenticator.canonical_id.encode("utf-8"),
        sb_cache.M_ue_bytes,
        timestamp_to_bytes(uplink.TS5),
    )
    if uplink.V1 != expected_V1:
        raise ValueError("uplink integrity check failed")

    combo_B = _combo_point(
        sb_cache.h_ue,
        sb_cache.ue_domain_pub,
        sb_cache.ue_pk_bytes,
        sb_cache.ue_P_bytes,
    )
    Q_B_point = sb_cache.m_B * combo_B
    Q_B_bytes = point_to_bytes(Q_B_point)

    V2 = hash_to_bytes(
        b"H2",
        uplink.ue_canonical.encode("utf-8"),
        authenticator.canonical_id.encode("utf-8"),
        sb_cache.M_ue_bytes,
        sb_cache.M_B_bytes,
        timestamp_to_bytes(ts6),
    )
    return Q_B_bytes, V2


################################################################################
# Phase 5 – Batch verification at the authenticator
################################################################################


@dataclass
class UplinkRequest:
    ue_canonical: str
    Q_bytes: bytes
    V1: bytes
    TS5: int
    M_bytes: bytes


def _vrf_eval(sk: bytes, epoch_id: bytes) -> Tuple[bytes, bytes]:
    h = hashlib.blake2s(key=sk, digest_size=32)
    h.update(epoch_id)
    rho = h.digest()
    h_proof = hashlib.blake2s(key=sk, digest_size=32)
    h_proof.update(b"proof" + epoch_id)
    proof = h_proof.digest()
    return rho, proof


def _deterministic_sample(rho: bytes, population: int, sample_size: int) -> List[int]:
    if sample_size >= population:
        return list(range(population))
    indices = []
    counter = 0
    used = set()
    while len(indices) < sample_size:
        digest = hashlib.blake2s(rho + counter.to_bytes(4, "big"), digest_size=32).digest()
        idx = int.from_bytes(digest, "big") % population
        counter += 1
        if idx in used:
            continue
        used.add(idx)
        indices.append(idx)
    return indices


def _derive_coefficients(rho: bytes, count: int) -> List[int]:
    coeffs = []
    for i in range(count):
        digest = hashlib.blake2s(rho + struct.pack(">I", i), digest_size=32).digest()
        coeffs.append(int.from_bytes(digest, "big") % curve.r)
    return coeffs


def batch_verify(
    authenticator: EntityState,
    requests: Sequence[UplinkRequest],
    *,
    epoch_id: bytes,
    sample_size: int,
    current_time: int,
    tolerance: int,
) -> Tuple[bool, bytes, bytes]:
    if authenticator.vrf_sk is None or authenticator.vrf_vk is None:
        raise ValueError("authenticator lacks VRF keys for batch mode")
    if not requests:
        return True, b"", b""

    rho, proof = _vrf_eval(authenticator.vrf_sk, epoch_id)

    # Level-1 checks
    subset = _deterministic_sample(rho, len(requests), sample_size)
    for idx in subset:
        item = requests[idx]
        _ensure_timestamp_fresh(item.TS5, current_time, tolerance)

        # Core equality
        left = authenticator.SK * point_from_bytes(item.Q_bytes)
        if point_to_bytes(left) != item.M_bytes:
            return False, rho, proof

        V1_expected = hash_to_bytes(
            b"H2",
            item.ue_canonical.encode("utf-8"),
            authenticator.canonical_id.encode("utf-8"),
            item.M_bytes,
            timestamp_to_bytes(item.TS5),
        )
        if V1_expected != item.V1:
            return False, rho, proof

    # Level-2 checks
    coeffs = _derive_coefficients(rho, len(requests))
    lhs_acc: Optional[ECp] = None
    rhs_acc: Optional[ECp] = None

    for weight, item in zip(coeffs, requests):
        _ensure_timestamp_fresh(item.TS5, current_time, tolerance)
        V1_expected = hash_to_bytes(
            b"H2",
            item.ue_canonical.encode("utf-8"),
            authenticator.canonical_id.encode("utf-8"),
            item.M_bytes,
            timestamp_to_bytes(item.TS5),
        )
        if V1_expected != item.V1:
            return False, rho, proof

        weighted_Q = weight * point_from_bytes(item.Q_bytes)
        weighted_M = weight * point_from_bytes(item.M_bytes)

        if lhs_acc is None:
            lhs_acc = weighted_Q.copy()
        else:
            lhs_acc.add(weighted_Q)

        if rhs_acc is None:
            rhs_acc = weighted_M.copy()
        else:
            rhs_acc.add(weighted_M)

    if lhs_acc is None or rhs_acc is None:
        raise ValueError("unexpected empty accumulators")

    lhs_checked = authenticator.SK * lhs_acc
    if point_to_bytes(lhs_checked) != point_to_bytes(rhs_acc):
        return False, rho, proof

    return True, rho, proof


################################################################################
# Convenience helpers for demonstrations and testing
################################################################################


def initialise_domains(domain_ids: Iterable[str]) -> Dict[str, DomainKGC]:
    return {domain_id: DomainKGC(domain_id=domain_id) for domain_id in domain_ids}


def example_setup() -> OfflineContext:
    """
    Build a default offline context with one UE and two satellites.
    """
    return perform_offline_phase(["ue-001"])


__all__ = [
    "DomainKGC",
    "EntityState",
    "SecureChannel",
    "SecureEnvelope",
    "UEPreAuthCache",
    "SBPreAuthCache",
    "UEOfflineRecord",
    "OfflineContext",
    "MutualAuthResult",
    "UplinkRequest",
    "initialise_domains",
    "create_entity",
    "establish_secure_channel",
    "pre_authenticate",
    "perform_offline_phase",
    "prepare_uplink",
    "finalize_authentication",
    "mutual_authentication",
    "authenticator_process_uplink",
    "batch_verify",
    "example_setup",
]
