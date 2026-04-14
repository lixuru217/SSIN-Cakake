#!/usr/bin/env python3
"""
Implementation of the Yang et al. (2024) conditional privacy-preserving
aggregate signature protocol for vehicular networks.

The module keeps the same overall flow as the SSIN, Guo2021, Liu2022, and
Zhu2023 models already used in the simulator while incorporating the
cryptographic modifications introduced by Yang2024. Those changes tighten the
scheme against public key replacement and coalition attacks by:

* Binding the message and full vehicle public key into the H3 hash used during
  signing and verification.
* Restructuring the signing equation to couple the secret randomness with the
  resulting signature component.
* Introducing a fifth hash function (H5) that allows the application server to
  validate every contribution inside an aggregate signature.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

from bn254 import big
from bn254 import curve
from bn254.ecp import ECp, generator


################################################################################
# Generic helpers
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


def normalize_scalar(value: int) -> int:
    return value % curve.r


def random_scalar() -> int:
    while True:
        candidate = big.rand(curve.r)
        if candidate != 0:
            return candidate


def scalar_mul_point(scalar: int, point_bytes: bytes) -> ECp:
    return (scalar % curve.r) * point_from_bytes(point_bytes)


def add_points(points: Iterable[ECp]) -> ECp:
    acc: Optional[ECp] = None
    for point in points:
        if acc is None:
            acc = point.copy()
        else:
            acc.add(point)
    if acc is None:
        raise ValueError("no points supplied")
    return acc


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


################################################################################
# Hash functions specialised for the protocol
################################################################################


def _hash_identity(real_id: str) -> bytes:
    return hashlib.sha256(real_id.encode("utf-8")).digest()


def hash_H1(t_pub: bytes, msk1_bytes: bytes, id1_bytes: bytes, validity_ts: int) -> bytes:
    return hash_to_bytes(
        b"Yang2024/H1",
        t_pub,
        msk1_bytes,
        id1_bytes,
        timestamp_to_bytes(validity_ts),
    )


def hash_H2(pseudo_id_encoded: bytes, p_pub: bytes, B_i: bytes) -> int:
    return hash_to_scalar(b"Yang2024/H2", pseudo_id_encoded, p_pub, B_i)


def hash_H3(
    pseudo_id_encoded: bytes,
    p_pub: bytes,
    message: bytes,
    vpk_encoded: bytes,
    ts: int,
    U_i: bytes,
) -> int:
    return hash_to_scalar(
        b"Yang2024/H3",
        pseudo_id_encoded,
        p_pub,
        message,
        vpk_encoded,
        timestamp_to_bytes(ts),
        U_i,
    )


def hash_H4(
    pseudo_id_encoded: bytes,
    p_pub: bytes,
    ts: int,
    vpk_encoded: bytes,
    message: bytes,
) -> int:
    return hash_to_scalar(
        b"Yang2024/H4",
        pseudo_id_encoded,
        p_pub,
        timestamp_to_bytes(ts),
        vpk_encoded,
        message,
    )


def hash_H5(*points: bytes) -> int:
    return hash_to_scalar(b"Yang2024/H5", *points)


################################################################################
# Data containers
################################################################################


@dataclass(frozen=True)
class PublicParameters:
    """Public parameters published by the trusted authority."""

    generator_bytes: bytes
    kgc_public_bytes: bytes
    tra_public_bytes: bytes

    def generator_point(self) -> ECp:
        return point_from_bytes(self.generator_bytes)

    def kgc_public_point(self) -> ECp:
        return point_from_bytes(self.kgc_public_bytes)

    def tra_public_point(self) -> ECp:
        return point_from_bytes(self.tra_public_bytes)


@dataclass(frozen=True)
class PseudoIdentity:
    """Conditional identity issued to a vehicle."""

    component1: bytes  # ID_{i,1}
    component2: bytes  # ID_{i,2}
    expiry_ts: int     # t_1

    def encode(self) -> bytes:
        return (
            _encode_length(self.component1)
            + _encode_length(self.component2)
            + timestamp_to_bytes(self.expiry_ts)
        )


@dataclass(frozen=True)
class VehiclePublicKey:
    """Complete public key held by a vehicle."""

    B_i: bytes
    R_i: bytes

    def encode(self) -> bytes:
        return _encode_length(self.B_i) + _encode_length(self.R_i)


@dataclass(frozen=True)
class VehicleSecretKey:
    """Complete secret key held by a vehicle."""

    c_i: int
    r_i: int


@dataclass(frozen=True)
class PartialSecretKey:
    """Partial secret key material returned by the KGC."""

    B_i: bytes
    c_i: int


@dataclass(frozen=True)
class Signature:
    """Single-message signature produced by a vehicle."""

    U_i: bytes
    delta_i: int


@dataclass(frozen=True)
class SignedBroadcast:
    """Bundle representing a message broadcast by a vehicle."""

    pseudo_id: PseudoIdentity
    public_key: VehiclePublicKey
    message: bytes
    timestamp: int
    signature: Signature


@dataclass(frozen=True)
class AggregateSignature:
    """Aggregate signature as produced by an RSU."""

    aggregate_point: bytes
    delta: int
    signature_count: int

    def __post_init__(self) -> None:
        if self.signature_count <= 0:
            raise ValueError("signature_count must be positive")


@dataclass(frozen=True)
class PseudoIdRequest:
    """Request generated by a vehicle to obtain a pseudo identity."""

    real_identity: str
    component1: bytes
    validity_ts: int


@dataclass(frozen=True)
class PseudoIdResponse:
    pseudo_identity: PseudoIdentity


################################################################################
# Trusted authority (KGC + TRA)
################################################################################


class TrustedAuthority:
    """Combines the KGC and TRA roles for the Yang2024 protocol."""

    def __init__(self) -> None:
        self._msk_kgc = random_scalar()
        self._msk_tra = random_scalar()

        base = generator()
        self._params = PublicParameters(
            generator_bytes=point_to_bytes(base),
            kgc_public_bytes=point_to_bytes(self._msk_kgc * base),
            tra_public_bytes=point_to_bytes(self._msk_tra * base),
        )

        self._identity_lookup: Dict[bytes, str] = {}
        self._issued_pseudo_ids: Dict[bytes, PseudoIdentity] = {}

    def public_parameters(self) -> PublicParameters:
        return self._params

    def issue_pseudo_identity(self, request: PseudoIdRequest) -> PseudoIdResponse:
        # Validate the provided point even though the hash no longer depends on it.
        point_from_bytes(request.component1)
        h1 = hash_H1(
            self._params.tra_public_bytes,
            scalar_to_bytes(self._msk_tra),
            request.component1,
            request.validity_ts,
        )

        rid_digest = _hash_identity(request.real_identity)
        if len(rid_digest) != len(h1):
            raise ValueError("identity hash and H1 output length mismatch")

        component2 = xor_bytes(rid_digest, h1)
        pseudo_id = PseudoIdentity(request.component1, component2, request.validity_ts)

        self._identity_lookup[rid_digest] = request.real_identity
        self._issued_pseudo_ids[pseudo_id.encode()] = pseudo_id

        return PseudoIdResponse(pseudo_id)

    def issue_partial_secret(self, pseudo_id: PseudoIdentity) -> PartialSecretKey:
        if pseudo_id.encode() not in self._issued_pseudo_ids:
            raise ValueError("unknown pseudo identity")

        b_i = random_scalar()
        B_i_point = b_i * generator()
        B_i_bytes = point_to_bytes(B_i_point)

        h2 = hash_H2(pseudo_id.encode(), self._params.kgc_public_bytes, B_i_bytes)
        c_i = normalize_scalar(b_i + self._msk_kgc * h2)

        return PartialSecretKey(B_i=B_i_bytes, c_i=c_i)

    def trace_vehicle(self, pseudo_id: PseudoIdentity) -> Optional[str]:
        point_from_bytes(pseudo_id.component1)
        h1 = hash_H1(
            self._params.tra_public_bytes,
            scalar_to_bytes(self._msk_tra),
            pseudo_id.component1,
            pseudo_id.expiry_ts,
        )
        rid_digest = xor_bytes(pseudo_id.component2, h1)
        return self._identity_lookup.get(rid_digest)


################################################################################
# Vehicle state
################################################################################


class VehicleState:
    """Maintains per-vehicle state and exposes signing operations."""

    def __init__(self, real_identity: str, parameters: PublicParameters) -> None:
        self.real_identity = real_identity
        self.parameters = parameters
        self._pending_id1: Optional[bytes] = None

        self.pseudo_identity: Optional[PseudoIdentity] = None
        self.partial_secret: Optional[PartialSecretKey] = None
        self.secret_key: Optional[VehicleSecretKey] = None
        self.public_key: Optional[VehiclePublicKey] = None

    def create_pseudo_id_request(self, validity_ts: int) -> PseudoIdRequest:
        a_i = random_scalar()
        id1_point = a_i * generator()
        id1_bytes = point_to_bytes(id1_point)
        self._pending_id1 = id1_bytes
        return PseudoIdRequest(self.real_identity, id1_bytes, validity_ts)

    def receive_pseudo_identity(self, response: PseudoIdResponse) -> None:
        pseudo_id = response.pseudo_identity
        if self._pending_id1 is None:
            raise ValueError("no pending pseudo identity request")
        if pseudo_id.component1 != self._pending_id1:
            raise ValueError("pseudo identity component mismatch")
        self.pseudo_identity = pseudo_id
        self._pending_id1 = None

    def install_partial_secret(self, partial: PartialSecretKey, secret_value: Optional[int] = None) -> None:
        if self.pseudo_identity is None:
            raise ValueError("pseudo identity not set")
        self.partial_secret = partial
        r_i = secret_value if secret_value is not None else random_scalar()
        self.secret_key = VehicleSecretKey(c_i=partial.c_i, r_i=r_i)
        R_i_point = r_i * generator()
        R_i_bytes = point_to_bytes(R_i_point)
        self.public_key = VehiclePublicKey(B_i=partial.B_i, R_i=R_i_bytes)

    def sign(self, message: bytes | str, timestamp: int, randomness: Optional[int] = None) -> SignedBroadcast:
        if isinstance(message, str):
            message_bytes = message.encode("utf-8")
        else:
            message_bytes = message

        if self.pseudo_identity is None or self.secret_key is None or self.public_key is None:
            raise ValueError("vehicle keys are not fully initialised")

        u_i = randomness if randomness is not None else random_scalar()
        U_i_point = u_i * generator()
        U_i_bytes = point_to_bytes(U_i_point)

        pseudo_encoded = self.pseudo_identity.encode()
        vpk_encoded = self.public_key.encode()

        h3 = hash_H3(
            pseudo_encoded,
            self.parameters.kgc_public_bytes,
            message_bytes,
            vpk_encoded,
            timestamp,
            U_i_bytes,
        )
        if h3 == 0:
            raise ValueError("hash H3 evaluated to zero; cannot compute modular inverse")

        h4 = hash_H4(
            pseudo_encoded,
            self.parameters.kgc_public_bytes,
            timestamp,
            vpk_encoded,
            message_bytes,
        )

        term = normalize_scalar(self.secret_key.r_i * h4 + self.secret_key.c_i)
        inv_h3 = pow(h3, -1, curve.r)
        delta = normalize_scalar(-u_i + inv_h3 * term)

        signature = Signature(U_i=U_i_bytes, delta_i=delta)
        return SignedBroadcast(
            pseudo_id=self.pseudo_identity,
            public_key=self.public_key,
            message=message_bytes,
            timestamp=timestamp,
            signature=signature,
        )


################################################################################
# Verification roles
################################################################################


class RSUVerifier:
    """Validates single signatures and produces aggregate signatures."""

    def __init__(self, parameters: PublicParameters) -> None:
        self.parameters = parameters

    def verify(self, broadcast: SignedBroadcast, now: Optional[int] = None) -> bool:
        if now is not None and broadcast.timestamp > now:
            return False
        if now is not None and broadcast.pseudo_id.expiry_ts < now:
            return False
        if broadcast.timestamp > broadcast.pseudo_id.expiry_ts:
            return False

        pseudo_encoded = broadcast.pseudo_id.encode()
        vpk_encoded = broadcast.public_key.encode()

        h2 = hash_H2(pseudo_encoded, self.parameters.kgc_public_bytes, broadcast.public_key.B_i)
        h3 = hash_H3(
            pseudo_encoded,
            self.parameters.kgc_public_bytes,
            broadcast.message,
            vpk_encoded,
            broadcast.timestamp,
            broadcast.signature.U_i,
        )
        h4 = hash_H4(
            pseudo_encoded,
            self.parameters.kgc_public_bytes,
            broadcast.timestamp,
            vpk_encoded,
            broadcast.message,
        )

        delta_point = scalar_mul_point(broadcast.signature.delta_i, self.parameters.generator_bytes)
        U_point = point_from_bytes(broadcast.signature.U_i)
        lhs = scalar_mul_point(h3, point_to_bytes(add_points([delta_point, U_point])))

        rhs_components: List[ECp] = [
            point_from_bytes(broadcast.public_key.B_i),
            scalar_mul_point(h4, broadcast.public_key.R_i),
            scalar_mul_point(h2, self.parameters.kgc_public_bytes),
        ]
        rhs = add_points(rhs_components)

        return point_to_bytes(lhs) == point_to_bytes(rhs)

    def aggregate(self, broadcasts: Sequence[SignedBroadcast]) -> AggregateSignature:
        if not broadcasts:
            raise ValueError("need at least one signature to aggregate")

        g_points: List[ECp] = []
        g_bytes: List[bytes] = []

        for broadcast in broadcasts:
            pseudo_encoded = broadcast.pseudo_id.encode()
            vpk_encoded = broadcast.public_key.encode()

            h3 = hash_H3(
                pseudo_encoded,
                self.parameters.kgc_public_bytes,
                broadcast.message,
                vpk_encoded,
                broadcast.timestamp,
                broadcast.signature.U_i,
            )
            delta_point = scalar_mul_point(broadcast.signature.delta_i, self.parameters.generator_bytes)
            U_point = point_from_bytes(broadcast.signature.U_i)
            combined = add_points([delta_point, U_point])
            g_point = scalar_mul_point(h3, point_to_bytes(combined))
            g_points.append(g_point)
            g_bytes.append(point_to_bytes(g_point))

        aggregate_point = add_points(g_points)
        delta = hash_H5(*g_bytes)
        return AggregateSignature(
            aggregate_point=point_to_bytes(aggregate_point),
            delta=delta,
            signature_count=len(broadcasts),
        )


class ApplicationServer:
    """Verifies aggregate signatures received from RSUs."""

    def __init__(self, parameters: PublicParameters) -> None:
        self.parameters = parameters

    def verify_aggregate(
        self,
        broadcasts: Sequence[SignedBroadcast],
        aggregate_signature: AggregateSignature,
        now: Optional[int] = None,
    ) -> bool:
        if not broadcasts:
            return False
        if aggregate_signature.signature_count != len(broadcasts):
            return False

        pseudo_encoded = [b.pseudo_id.encode() for b in broadcasts]
        upsilon_points: List[ECp] = []

        for idx, broadcast in enumerate(broadcasts):
            if broadcast.timestamp > broadcast.pseudo_id.expiry_ts:
                return False
            if now is not None and (broadcast.timestamp > now or broadcast.pseudo_id.expiry_ts < now):
                return False

            encoded = pseudo_encoded[idx]
            vpk_encoded = broadcast.public_key.encode()

            h2_i = hash_H2(encoded, self.parameters.kgc_public_bytes, broadcast.public_key.B_i)
            h4_i = hash_H4(
                encoded,
                self.parameters.kgc_public_bytes,
                broadcast.timestamp,
                vpk_encoded,
                broadcast.message,
            )

            upsilon_points.append(
                add_points(
                    [
                        point_from_bytes(broadcast.public_key.B_i),
                        scalar_mul_point(h4_i, broadcast.public_key.R_i),
                        scalar_mul_point(h2_i, self.parameters.kgc_public_bytes),
                    ]
                )
            )

        aggregate_rhs = add_points(upsilon_points)
        if point_to_bytes(aggregate_rhs) != aggregate_signature.aggregate_point:
            return False

        delta_check = hash_H5(*(point_to_bytes(point) for point in upsilon_points))
        return delta_check == normalize_scalar(aggregate_signature.delta)


__all__ = [
    "AggregateSignature",
    "ApplicationServer",
    "PartialSecretKey",
    "PseudoIdRequest",
    "PseudoIdResponse",
    "PseudoIdentity",
    "PublicParameters",
    "RSUVerifier",
    "Signature",
    "SignedBroadcast",
    "TrustedAuthority",
    "VehiclePublicKey",
    "VehicleSecretKey",
    "VehicleState",
]
