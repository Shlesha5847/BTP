# utils/symmetric.py
# ============================================================
# Simple symmetric encryption based on a bytes KEY
# Used for Enc_KEY(M) and Dec_KEY(M) in the paper (demo version)
# ============================================================

import os
import hashlib


def gen_sym_key(length: int = 32) -> bytes:
    """Generate a random symmetric key."""
    return os.urandom(length)


def kdf_from_key(KEY: bytes, length: int) -> bytes:
    """
    Derive a pseudorandom keystream from a bytes KEY.
    1) Hash KEY with SHA-256
    2) Repeat / truncate to desired length
    """
    digest = hashlib.sha256(KEY).digest()
    keystream = (digest * ((length // len(digest)) + 1))[:length]
    return keystream


def sym_enc(KEY: bytes, plaintext: bytes) -> bytes:
    """XOR encryption: CS = Enc_KEY(M)."""
    ks = kdf_from_key(KEY, len(plaintext))
    return bytes(p ^ k for p, k in zip(plaintext, ks))


def sym_dec(KEY: bytes, ciphertext: bytes) -> bytes:
    """XOR decryption: M = Dec_KEY(CS)."""
    return sym_enc(KEY, ciphertext)  # XOR is its own inverse
