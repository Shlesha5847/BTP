from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from cpabe.utils.kdf import kdf
from cpabe.utils.hashing import hash_to_ZR


# ============================================================
# Final decrypt (User side)
# ============================================================
def final_decrypt(group, pk, sk, C_dec, ct):
    """
    final_decrypt_flawed(pk, SK, C_dec, CT) -> M

    KEY = Ce / C_dec, because:

       Ce   = KEY * e(g,g)^{S_w·s}
       C_dec= e(g,g)^{S_w·s}

    So:

       KEY = Ce / C_dec

    Then:

       M   = Dec_KEY(CS)

    Finally verify VK = (g^{h(KEY)}, g^{h(M)}).
    """
    g = pk["g"]

    Ce = ct["Ce"]
    CS = ct["CS"]
    VK1 = ct["VK1"]
    VK2 = ct["VK2"]

    # 1) Recover KEY
    KEY = Ce / C_dec  # GT element

    # 2) Symmetric decryption
    sym_key = kdf(group,KEY)
    sym = SymmetricCryptoAbstraction(sym_key)
    M_bytes = sym.decrypt(CS)

    # 3) Verification
    h_key = hash_to_ZR(group,KEY)
    h_msg = hash_to_ZR(group,M_bytes)
    VK1_chk = g**h_key
    VK2_chk = g**h_msg

    if VK1 != VK1_chk or VK2 != VK2_chk:
        raise Exception("Verification failed (flawed scheme).")

    return M_bytes
