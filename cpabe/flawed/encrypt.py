from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.pairinggroup import GT, pair,ZR

from cpabe.utils.kdf import kdf
from cpabe.utils.hashing import hash_to_ZR


# ============================================================
# Encrypt
# ============================================================
def encrypt(group, pk, mk, message_bytes, policy_attrs):
    """
    Encrypt(pk, M, P) -> CT

    P = policy_attrs (AND-policy).
    Let S_w = sum_{a in P} w[a].

    Steps:
      1) Ensure w[a] exists for all a in P (choose random if not).
      2) Compute S_w = Σ w[a].
      3) Choose s ∈ Z_p, KEY ∈ GT randomly.
      4) Ce   = KEY * e(g,g)^{S_w·s}
      5) C_hat= g^s
      6) CS   = Enc_KEY(M)
      7) VK   = (g^{h(KEY)}, g^{h(M)})

    CT = { Ce, C_hat, CS, VK1, VK2, policy_attrs }
    """
    if mk is None:
        raise Exception("Run setup() first so self.mk is initialized.")

    g = pk["g"]
    Y = pk["Y"]  # not strictly needed, but kept for structural analogy
    group = group
    w_map = mk["w"]

    # 1) Ensure w[a] defined, compute S_w
    S_w = group.init(ZR, 0)
    for attr in policy_attrs:
        if attr not in w_map:
            w_map[attr] = group.random(ZR)
        S_w += w_map[attr]

    # 2) Choose s, KEY
    s = group.random(ZR)
    KEY = group.random(GT)

    # 3) Ce = KEY * e(g,g)^{S_w·s}
    Ce = KEY * (pair(g, g) ** (S_w * s))

    # 4) C_hat = g^s
    C_hat = g**s

    # 5) Symmetric encryption
    sym_key = kdf(self.group ,KEY)
    sym = SymmetricCryptoAbstraction(sym_key)
    CS = sym.encrypt(message_bytes)

    # 6) Verification tag
    h_key = hash_to_ZR(self.group, KEY)
    h_msg = hash_to_ZR(group, message_bytes)
    VK1 = g**h_key
    VK2 = g**h_msg

    ct = {
        "Ce": Ce,
        "C_hat": C_hat,
        "CS": CS,
        "VK1": VK1,
        "VK2": VK2,
        "policy_attrs": list(policy_attrs),
    }
    return ct
