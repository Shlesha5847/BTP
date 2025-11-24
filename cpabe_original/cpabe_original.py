from __future__ import annotations
from dataclasses import dataclass
from typing import Set, Optional, List
import hashlib
import secrets


# ---------------------------------------------------------------------
# Utility hash
# ---------------------------------------------------------------------

def H(*parts: str) -> int:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode())
    return int.from_bytes(h.digest(), "big")


# ---------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------

@dataclass
class PublicParams:
    description: str
    pk_random: int


@dataclass
class MasterKey:
    secret: int


@dataclass
class SecretKey:
    # ❗ ORIGINAL SCHEME:  NOT identity-bound
    attributes: Set[str]
    sk_tag: int   # derived ONLY from attributes + master key (no identity)


@dataclass
class Ciphertext:
    policy: Set[str]
    ct_tag: int
    nonce: int
    enc: bytes


# ---------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------

def setup():
    pk = PublicParams(
        description="Original Sensors CP-ABE (FLAWED - no identity binding)",
        pk_random=secrets.randbits(128),
    )
    msk = MasterKey(secret=secrets.randbits(256))
    return pk, msk


# ---------------------------------------------------------------------
# Key Generation (FLAWED)
# ---------------------------------------------------------------------

def keygen(msk, attributes: Set[str]):
    """
    Original flawed scheme:
    ✔ NO user identity involved
    ✔ sk_tag derived only from master key + attributes
    ❗ Vulnerable to collusion: different users with different attributes can combine them
    """

    attrs = ",".join(sorted(attributes))

    # ❗ NOTE: No user-id here → flaw
    sk_tag = H("SK", str(msk.secret), attrs)

    return SecretKey(attributes=set(attributes), sk_tag=sk_tag)


# ---------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------

def derive_key(tag: int, nonce: int) -> bytes:
    h = hashlib.sha256()
    h.update(tag.to_bytes(32, "big"))
    h.update(nonce.to_bytes(16, "big"))
    return h.digest()


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(pk, policy: Set[str], message: str):
    """
    Original CP-ABE encryption:
    ✔ Depends ONLY on policy
    ✔ No identity-binding
    ❗ Anybody who satisfies policy (or combines attributes) can decrypt
    """
    nonce = secrets.randbits(128)
    policy_str = ",".join(sorted(policy))

    ct_tag = H("POLICY", policy_str)  # same as before but no identity binding

    key = derive_key(ct_tag, nonce)
    enc = xor(message.encode(), key)

    return Ciphertext(policy=set(policy), ct_tag=ct_tag, nonce=nonce, enc=enc)


# ---------------------------------------------------------------------
# Decryption (FLAWED)
# ---------------------------------------------------------------------

def decrypt(ct: Ciphertext, sk: SecretKey):
    """
    Original scheme:
    ✔ Only checks attributes match
    ❗ Does NOT check identity
    ❗ Collusion possible
    """
    # must satisfy policy
    if not ct.policy.issubset(sk.attributes):
        raise PermissionError("Attributes do not satisfy policy")

    # derive key and decrypt
    key = derive_key(ct.ct_tag, ct.nonce)
    pt = xor(ct.enc, key)

    try:
        return pt.decode()
    except:
        raise PermissionError("Decryption failed (wrong key)")


# ---------------------------------------------------------------------
# Collusion function — this time allowed
# ---------------------------------------------------------------------

def colluding_decrypt(ct: Ciphertext, keys: List[SecretKey]):
    """
    FLAWED version:
    ✔ Collusion ALLOWED
    ✔ Merge attributes of multiple users
    """

    # merge attributes from all keys
    merged_attrs = set()
    for k in keys:
        merged_attrs |= k.attributes

    # rebuild a "synthetic" key with union attributes
    fake_tag_attrs = ",".join(sorted(merged_attrs))
    fake_sk_tag = H("SK_FAKE", fake_tag_attrs)   # same as Sensors flaw: no identity

    fake_sk = SecretKey(attributes=merged_attrs, sk_tag=fake_sk_tag)

    return decrypt(ct, fake_sk)
