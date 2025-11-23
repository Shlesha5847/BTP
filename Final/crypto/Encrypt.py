# crypto/Encrypt.py
# ============================================================
# Encryption phase (pure Python demo version)
# Generates CT (ABE policy info), CS (symmetric ciphertext),
# and VK (verification tag).
# ============================================================

import os
import hashlib
from utils.symmetric import sym_enc, gen_sym_key


class Encryptor:
    def __init__(self, PK: dict):
        """
        PK: public key from AA (we mainly use 'universe' here).
        """
        self.PK = PK

    def encrypt(self, message: bytes, AS):
        """
        Encrypt(PK, M, AS) = CT0 = (CT, CS, VK)

        AS: list or set of attributes required to decrypt.
        """

        AS = list(AS)

        # Symmetric KEY (this replaces GT element KEY in the paper)
        KEY = gen_sym_key(32)

        # CS = Enc_KEY(M)
        CS = sym_enc(KEY, message)

        # Mimic "C components" as random salts / hashes
        salt_ct = os.urandom(16)
        CT = {
            "AS": AS,
            "salt": salt_ct.hex(),   # just to show something in CT
        }

        # VK = (hash(KEY), hash(M)) similar to g^{h(KEY)}, g^{h(M)}
        h_KEY = hashlib.sha256(KEY).hexdigest()
        h_M = hashlib.sha256(message).hexdigest()
        VK = (h_KEY, h_M)

        CT0 = {
            "CT": CT,
            "CS": CS,
            "VK": VK,
            # For this pure-Python demo, we keep KEY inside CT0.
            # In a real scheme, KEY is hidden by CP-ABE math.
            "_KEY": KEY,
        }
        return CT0
