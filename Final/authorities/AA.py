# authorities/AA.py
# ============================================================
# Attribute Authority (AA)
# - Setup(k) -> PK (public info)
# - KeyGen(ID_i, AU*) -> SK (user secret key)
# - Adds trace-related tags (QID_i, PSK_IDi) conceptually
# ============================================================

import os
import hashlib


class AttributeAuthority:
    def __init__(self, universe_attributes):
        """
        universe_attributes: U = ["Doctor", "Cardiology", ...]
        """
        self.U = list(universe_attributes)

        # In real CP-ABE: alpha, beta, t_i in Z_p, group elements, etc.
        # Here: we simulate with random bytes for demo.
        self.master_secret = os.urandom(32)  # global master (simulated)
        self.attr_secrets = {
            att: os.urandom(16) for att in self.U
        }  # one secret per attribute

        # Public key can conceptually contain "public attribute labels"
        self.PK = {
            "universe": self.U
        }

        # For trace-like behavior, we simulate P and Tpub_AA as random bytes
        self.P = os.urandom(16)        # simulated "P"
        self.Tpub_AA = os.urandom(16)  # simulated "alpha * P"

    # ---------------------- h2 hash ----------------------
    def hash_h2(self, ID_i: dict, QID_i: bytes) -> bytes:
        data = (str(ID_i)).encode("utf-8") + QID_i
        return hashlib.sha256(data).digest()

    # ---------------------- KeyGen -----------------------
    def keygen_with_trace(self, ID_i: dict, AU_star):
        """
        KeyGen(ID_i, AU*) -> SK

        AU_star : list or set of attributes for this user
        """
        AU_star = set(AU_star)

        # In paper: d_i random, QID_i = d_i * P, PSK_IDi = d_i + h2(...) * alpha
        # Here: we simulate QID_i and PSK_IDi as random + hash-based values.
        d_i = os.urandom(16)
        QID_i = hashlib.sha256(d_i + b"QID").digest()

        h2_val = self.hash_h2(ID_i, QID_i)
        PSK_IDi = hashlib.sha256(d_i + h2_val + self.master_secret).digest()

        # Simulate user attribute components (user-specific keys)
        attr_keys = {}
        for att in AU_star:
            if att not in self.attr_secrets:
                raise ValueError(f"Unknown attribute: {att}")
            attr_keys[att] = hashlib.sha256(
                self.attr_secrets[att] + d_i
            ).digest()

        SK = {
            "S": AU_star,       # attribute set
            "PSK_IDi": PSK_IDi,
            "QID_i": QID_i,
            "attr_keys": attr_keys,
        }
        return SK
