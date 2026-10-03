"""Pure-python secp256k1 ECDSA helpers and canonical payload digests.

No external dependencies. Signatures are ``(r, s, v)`` triples with
``v in {0, 1}`` so the signer address can be recovered from the digest,
mirroring the usual Ethereum-style flow (but using sha3-256 from the
standard library for addresses and payload hashing).
"""

from __future__ import annotations

import hashlib
import hmac

# secp256k1 domain parameters.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

ZERO_ADDRESS = "0x" + "0" * 40

# A point is a tuple (x, y); None is the point at infinity.


def _is_on_curve(point) -> bool:
    if point is None:
        return True
    x, y = point
    return (y * y - x * x * x - 7) % P == 0


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p == q:
        m = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        m = (y2 - y1) * pow((x2 - x1) % P, -1, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k: int, point):
    if k % N == 0 or point is None:
        return None
    k %= N
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def private_to_public(privkey: int):
    if not 1 <= privkey < N:
        raise ValueError("private key out of range")
    return point_mul(privkey, G)


def address_of(point) -> str:
    """Derive a hex address from a public key point."""
    x, y = point
    raw = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return "0x" + hashlib.sha3_256(raw).digest()[-20:].hex()


def address_of_private(privkey: int) -> str:
    return address_of(private_to_public(privkey))


def _rfc6979_nonce(privkey: int, digest: bytes) -> int:
    """Deterministic nonce generation per RFC 6979 (HMAC-SHA256)."""
    x = privkey.to_bytes(32, "big")
    h1 = digest.rjust(32, b"\x00")[-32:]
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(privkey: int, digest: bytes) -> tuple[int, int, int]:
    """Return an (r, s, v) signature over a 32-byte digest, low-s normalized."""
    if len(digest) > 32:
        raise ValueError("digest too long")
    z = int.from_bytes(digest, "big")
    while True:
        k = _rfc6979_nonce(privkey, digest)
        rx, ry = point_mul(k, G)
        r = rx % N
        if r == 0:
            continue
        s = (pow(k, -1, N) * (z + r * privkey)) % N
        if s == 0:
            continue
        v = ry & 1
        if s > N // 2:
            s = N - s
            v ^= 1
        return (r, s, v)


def _decompress(x: int, odd: int):
    if not 0 <= x < P:
        return None
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if (y & 1) != odd:
        y = P - y
    point = (x, y)
    return point if _is_on_curve(point) else None


def recover(digest: bytes, sig: tuple[int, int, int]):
    """Recover the public key point from an (r, s, v) signature."""
    r, s, v = sig
    if not (1 <= r < N and 1 <= s <= N // 2 and v in (0, 1)):
        raise ValueError("malformed signature")
    point_r = _decompress(r, v)
    if point_r is None:
        raise ValueError("invalid recovery point")
    z = int.from_bytes(digest, "big")
    r_inv = pow(r, -1, N)
    # Q = r^-1 * (s*R - z*G)
    q = point_mul(r_inv, point_add(point_mul(s, point_r), point_mul(-z % N, G)))
    if q is None:
        raise ValueError("recovered point at infinity")
    return q


def recover_address(digest: bytes, sig: tuple[int, int, int]) -> str:
    return address_of(recover(digest, sig))


def verify(point, digest: bytes, sig: tuple[int, int, int]) -> bool:
    try:
        return recover(digest, sig) == point
    except ValueError:
        return False


# --- Canonical payload encoding -------------------------------------------

_DOMAIN = b"SAFEWALLET-V1"


def _encode_scalar(field) -> bytes:
    if isinstance(field, bool):
        raise TypeError("booleans are not encodable fields")
    if isinstance(field, int):
        if field < 0:
            raise TypeError("negative integers are not encodable fields")
        return field.to_bytes(32, "big")
    if isinstance(field, str):
        return field.encode("utf-8")
    if isinstance(field, (bytes, bytearray)):
        return bytes(field)
    raise TypeError(f"unsupported field type: {type(field)!r}")


def encode_fields(*fields) -> bytes:
    """Length-prefixed canonical encoding; lists/tuples encode recursively."""
    out = bytearray()
    for field in fields:
        if isinstance(field, (list, tuple)):
            blob = encode_fields(*field)
        else:
            blob = _encode_scalar(field)
        out += len(blob).to_bytes(4, "big")
        out += blob
    return bytes(out)


def payload_digest(op: str, *fields) -> bytes:
    """Domain-separated digest binding an operation tag to its fields."""
    return hashlib.sha3_256(_DOMAIN + encode_fields(op, *fields)).digest()
