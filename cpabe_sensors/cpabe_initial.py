from __future__ import annotations
from dataclasses import dataclass
from typing import Set, Optional, List
import hashlib
import secrets


def H(*parts: str) -> int:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode())
    return int.from_bytes(h.digest(), 'big')


@dataclass
class PublicParams:
    description: str
    pk_random: int


@dataclass
class MasterKey:
    secret: int


@dataclass
class SecretKey:
    user_id: str
    attributes: Set[str]
    sk_tag: int   # derived from (msk, user identity, attributes)


@dataclass
class Ciphertext:
    policy: Set[str]
    bound_user: Optional[str]
    ct_tag: int
    nonce: int
    enc: bytes


def setup():
    pk = PublicParams(
        description="Toy CP-ABE",
        pk_random=secrets.randbits(128),
    )
    msk = MasterKey(
        secret=secrets.randbits(256)
    )
    return pk, msk


def keygen(msk, user_id, attributes):
    attrs = ",".join(sorted(attributes))
    sk_tag = H("SK", str(msk.secret), user_id, attrs)
    return SecretKey(user_id=user_id, attributes=set(attributes), sk_tag=sk_tag)


def derive_key(tag: int, nonce: int) -> bytes:
    h = hashlib.sha256()
    h.update(tag.to_bytes(32, "big"))
    h.update(nonce.to_bytes(16, "big"))
    return h.digest()


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(pk, policy, message, bound_user=None):
    nonce = secrets.randbits(128)
    policy_str = ",".join(sorted(policy))

    # Encryption tag depends ONLY on policy + optional user binding
    base_tag = H("POLICY", policy_str)

    if bound_user:
        ct_tag = H("BIND", str(base_tag), bound_user)
    else:
        ct_tag = base_tag

    key = derive_key(ct_tag, nonce)
    enc = xor(message.encode(), key)

    return Ciphertext(policy=set(policy), bound_user=bound_user,
                      ct_tag=ct_tag, nonce=nonce, enc=enc)


def decrypt(ct, sk):
    # ID binding check
    if ct.bound_user and sk.user_id != ct.bound_user:
        raise PermissionError("Ciphertext bound to different identity")

    # Attribute check
    if not ct.policy.issubset(sk.attributes):
        raise PermissionError("Attribute policy not satisfied")

    # Reconstruct exact tag
    reconstructed_tag = ct.ct_tag

    # Derive key and decrypt
    key = derive_key(reconstructed_tag, ct.nonce)
    pt = xor(ct.enc, key)

    try:
        return pt.decode()
    except:
        raise PermissionError("Decryption failed: wrong key")


def colluding_decrypt(ct, keys: List[SecretKey]):
    # Collusion prevention: different identities
    ids = {k.user_id for k in keys}
    if len(ids) > 1:
        raise PermissionError("Collusion blocked: different identities")

    # Merge attributes
    merged_attrs = set()
    for k in keys:
        merged_attrs |= k.attributes

    fake_key = SecretKey(user_id=list(ids)[0],
                         attributes=merged_attrs,
                         sk_tag=keys[0].sk_tag)

    return decrypt(ct, fake_key)
