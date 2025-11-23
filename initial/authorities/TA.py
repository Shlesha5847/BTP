# ============================================================
# Trace Authority functions managing:
# Anonymous ID, h1 hashing, XOR data hiding
# ============================================================

import hashlib
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1

group = PairingGroup('MNT224')

class TraceAuthority:
    def __init__(self):
        self.beta = group.random(ZR)
        self.P = group.random(G1)
        self.Tpub_TA = self.beta * self.P
        self.registry = {}

    def h1(self, raw):
        return group.init(ZR, int.from_bytes(hashlib.sha256(raw).digest(), "big"))

    def register(self, RID, ID1, T):
        concat = (RID + ID1 + T).encode()
        h = self.h1(concat)
        xor_bytes = bytes(a ^ b for a, b in zip(RID.encode(), int(h).to_bytes(len(RID), 'big')))
        ID2 = xor_bytes.hex()

        ID = {"ID1": ID1, "ID2": ID2, "T": T}
        self.registry[RID] = ID
        return ID
