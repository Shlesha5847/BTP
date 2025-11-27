# ============================================================
# Final decrypt (User side)
# ============================================================
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.pairinggroup import pair

from cpabe.utils.kdf import kdf
from cpabe.utils.hashing import hash_to_ZR

def final_decrypt(group, pk, sk, C_star, ct):
    """
    final_decrypt_fixed(PK, SK, C*, CT) -> M

    This recovers KEY from Ce, C_hat, D'*, and C*:

        D'*  = g^(α - r + h_i)
        G*   = g^(r + |P| h_i)
        C*   = e(G*, C_hat) = e(g,g)^{(r + |P| h_i) s}

    Denominator in KEY0*:

        denom = e(C_hat, D'*) * C*
              = e(g^s, g^(α - r + h_i)) * e(g,g)^{(r + |P| h_i) s}
              = e(g,g)^{ (α - r + h_i) s + (r + |P|h_i) s }
              = e(g,g)^{ (α + (|P|+1) h_i) s }

    Numerator:

        Ce = KEY * e(g,g)^{α s}

    So:

        KEY0* = Ce / denom
              = KEY * e(g,g)^{α s} / e(g,g)^{(α + (|P|+1) h_i) s}
              = KEY * e(g,g)^{ -( |P|+1 ) h_i s }

    Let:

        φ_i = e(g^{h_i}, C_hat) = e(g, g)^{h_i s}

    Then:

        φ_i^{(|P|+1)} = e(g,g)^{ (|P|+1) h_i s }

    Hence we can recover KEY:

        KEY = KEY0* * φ_i^{(|P|+1)}

    Only a user with the correct h_i can compute φ_i and thus remove
    the extra exponent. Colluding users with mixed SK components from
    different IDs will have exponents involving both h_A, h_B, and
    cannot find a single φ to fix it.
    """
    g = pk["g"]
    h_i = sk["h_i"]
    D_prime_star = sk["D_prime_star"]

    Ce = ct["Ce"]
    C_hat = ct["C_hat"]
    CS = ct["CS"]
    VK1 = ct["VK1"]
    VK2 = ct["VK2"]
    policy = ct["policy_attrs"]
    k = len(policy)  # |P|

    # 1) Compute KEY0* = Ce / ( e(C_hat, D'*) * C* )
    denom = pair(C_hat, D_prime_star) * C_star
    KEY0_star = Ce / denom

    # 2) Compute φ_i = e(g^{h_i}, C_hat) = e(g, g)^{h_i s}
    g_hi = g**h_i
    phi_i = pair(g_hi, C_hat)

    # 3) Recover KEY = KEY0* * φ_i^{k+1}
    KEY = KEY0_star * (phi_i ** (k + 1))

    # 4) Symmetric decrypt with KEY
    sym_key = kdf(group , KEY)
    sym = SymmetricCryptoAbstraction(sym_key)
    M_bytes = sym.decrypt(CS)

    # 5) Verify VK
    h_key = hash_to_ZR(group,KEY)
    h_msg = hash_to_ZR(group,M_bytes)

    VK1_check = g**h_key
    VK2_check = g**h_msg

    if VK1 != VK1_check or VK2 != VK2_check:
        raise Exception("Verification failed (fixed scheme): VK mismatch.")

    return M_bytes
