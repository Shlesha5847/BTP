# authorities/TA.py
# ============================================================
# Trace Authority (TA)
# - Registers user with real ID and creates anonymous ID_i
# - Simulates ID2 = RID XOR h1(...)
# ============================================================

import hashlib


class TraceAuthority:
    def __init__(self):
        # registry: real RID -> anonymous ID_i
        # RID is real ID of user , ID_i is anonymous. maintains this mapping
        self.registry = {}

    def h1(self, rid: str, id1: str, t: str) -> bytes:
        """Hash-based h1 used for generating ID2."""
        concat = (rid + id1 + t).encode("utf-8")
        return hashlib.sha256(concat).digest()
    #Used to compute a masked version of RID.

    def register(self, RID: str, ID1: str, T: str):
        """
        Input:
            RID : real identity
            ID1 : user-chosen pseudonym
            T   : validity period/string

        Output:
            ID_i = {ID1, ID2, T} , 
            ID1 = pseudonym
            ID2 = masked identity
            T = time period
        """
        h = self.h1(RID, ID1, T)

        rid_bytes = RID.encode("utf-8")
        h_bytes = h[: len(rid_bytes)]
        xor_bytes = bytes(a ^ b for a, b in zip(rid_bytes, h_bytes))
        ID2 = xor_bytes.hex()

        ID_i = {"ID1": ID1, "ID2": ID2, "T": T}
        self.registry[RID] = ID_i
        return ID_i

    def trace(self, leaked_ID_i: dict):
        """
        Given an anonymous ID_i, try to find the real RID.
        """
        for rid, stored in self.registry.items():
            if stored == leaked_ID_i:
                return rid
        return None
