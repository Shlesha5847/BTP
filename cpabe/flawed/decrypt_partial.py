from charm.toolbox.pairinggroup import  pair
# ============================================================
# Partial decrypt (AC / Server side)
# ============================================================
def partial_decrypt(group, pk, ct, sk):
    """
    partial_decrypt_flawed(pk, CT, SK) -> (C_dec, CT)

    AC/server side logic.

    For policy P, user SK has QID[a] = g^{w[a]} for each a in their S.

    If user has all attributes in P:

        G = ∏_{a in P} QID[a] = g^{Σ w[a]} = g^{S_w}
        C_dec = e(G, C_hat) = e(g^{S_w}, g^s) = e(g,g)^{S_w·s}

    This matches the exponent in Ce:

        Ce = KEY * e(g,g)^{S_w·s}

    so the user can compute KEY = Ce / C_dec.

    FLAW:
      If user A and B each hold a subset of P, they can pool
      their QID[a] to reconstruct the same G and pass this step
      as if they were a single user.
    """
    C_hat = ct["C_hat"]
    policy = set(ct["policy_attrs"])

    user_attrs = sk["attrs"]
    if not policy.issubset(user_attrs):
        raise Exception("User attributes do not satisfy policy (flawed scheme).")

    QID = sk["QID"]

    # G = product of QID[a] over policy
    G = None
    for attr in policy:
        if attr not in QID:
            raise Exception(f"Missing QID for attribute '{attr}'")
        if G is None:
            G = QID[attr]
        else:
            G *= QID[attr]

    C_dec = pair(G, C_hat)
    return C_dec, ct
