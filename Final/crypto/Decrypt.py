# crypto/Decrypt.py
# ============================================================
# Final Decryption after partial decrypt (pure Python version)
# ============================================================

import hashlib
from utils.symmetric import sym_dec


class FinalDecryptor:
    def __init__(self):
        pass

    def final_decrypt(self, C, CT0):
        """
        Inputs:
            C    : Output of partial decrypt (simulated as b"OK")
            CT0  : { CT, CS, VK, _KEY }
        Output:
            plaintext bytes
        """

        CT = CT0["CT"]
        CS = CT0["CS"]
        VK = CT0["VK"]
        KEY_prime = CT0["_KEY"]   # In real CP-ABE, derived via math

        plaintext = sym_dec(KEY_prime, CS)

        # Verify VK'
        h_KEY = hashlib.sha256(KEY_prime).hexdigest()
        h_M = hashlib.sha256(plaintext).hexdigest()
        VK_prime = (h_KEY, h_M)

        if VK_prime != VK:
            raise ValueError("Verification failed — data tampered or wrong key.")

        return plaintext
