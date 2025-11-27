from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.pairinggroup import GT, ZR

from cpabe.utils.kdf import kdf
from cpabe.utils.hashing import hash_to_ZR


# ============================================================
# Encrypt: same structure as before (no change)
# ============================================================
def encrypt(group, pk, message_bytes, policy_attrs):
    """
    Encrypt(PK, M, P) -> CT

    Input:
      - pk: public key
      - message_bytes: plaintext M
      - policy_attrs: list/set of attributes defining an AND-policy P

    Steps:
      1) Choose s ∈ Z_p randomly
      2) Choose KEY ∈ GT randomly
      3) Ce = KEY * Y^s
      4) C_hat = g^s
      5) CS = Enc_KEY(M)
      6) VK = (g^{h(KEY)}, g^{h(M)})

    Output:
      CT = { Ce, C_hat, CS, VK1, VK2, policy_attrs }
    """
    g = pk["g"]
    Y = pk["Y"]
    group = group

    # random s in Z_p
    s = group.random(ZR)

    # random KEY in GT
    KEY = group.random(GT)

    # Ce = KEY * (Y^s) = KEY * e(g,g)^(α s)
    Ce = KEY * (Y**s)

    # C_hat = g^s
    C_hat = g**s

    # Symmetric encryption using KEY
    sym_key = kdf(group, KEY)
    sym = SymmetricCryptoAbstraction(sym_key)
    CS = sym.encrypt(message_bytes)

    # Verification tag
    h_key = hash_to_ZR(group,KEY)
    h_msg = hash_to_ZR(group,message_bytes)
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
