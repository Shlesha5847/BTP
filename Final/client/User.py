# client/User.py
# ============================================================
# User-side client (pure Python demo)
# - Holds SK and ID_i
# - Creates token (PSK_IDi + attributes)
# - Performs final decryption and verification (VK check)
# ============================================================

import hashlib
from utils.symmetric import sym_dec


class UserClient:
    def __init__(self, user_id: str, ID_i: dict, SK: dict, aa):
        self.user_id = user_id
        self.ID_i = ID_i
        self.SK = SK
        self.aa = aa

    # ---------- Token creation ----------
    def create_token(self):
        """
        Token = (PSK_IDi, AU*, ID_i)
        """
        return {
            "PSK_IDi": self.SK["PSK_IDi"],
            "AU_star": list(self.SK["S"]),
            "ID_i": self.ID_i,
        }

    # ---------- Final decryption ----------
    def final_decrypt(self, C, CT0):
        """
        In this pure-Python demo:
            - KEY is stored (as _KEY) in CT0 (simulating ABE-derived key)
            - We still verify VK = (hash(KEY), hash(M))
        """
        CT = CT0["CT"]
        CS = CT0["CS"]
        VK = CT0["VK"]
        KEY = CT0["_KEY"]

        # Decrypt
        plaintext = sym_dec(KEY, CS)

        # Verify VK'
        h_KEY = hashlib.sha256(KEY).hexdigest()
        h_M = hashlib.sha256(plaintext).hexdigest()
        VK_prime = (h_KEY, h_M)

        if VK_prime != VK:
            raise ValueError("Verification failed: VK' != VK (tampered data?)")

        return plaintext
