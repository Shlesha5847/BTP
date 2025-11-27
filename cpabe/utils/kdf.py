# ============================================================
# Helper: KDF from GT -> bytes
# ============================================================
import hashlib
def kdf(group, K_gt):
    """
    Derive a symmetric key from a GT element using SHA-256 over its
    serialized byte representation.
    """
    K_bytes = group.serialize(K_gt)
    return hashlib.sha256(K_bytes).digest()
