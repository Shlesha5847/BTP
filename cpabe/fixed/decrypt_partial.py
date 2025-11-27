# ============================================================
# Partial decrypt (AC/server side)
# ============================================================

from charm.toolbox.pairinggroup import pair 
def partial_decrypt(group, pk, ct, sk):
    """
    partial_decrypt_fixed(PK, CT, SK) -> (C_star, CT)

    AC-side decryption step using D*_j (identity-bound components).

    Let P = policy_attrs.
    In the fixed scheme:

        Dj_star[attr] = g^{r_attr + h_i}

    For the policy attributes:

        G* = ∏_{attr ∈ P} Dj_star[attr]
           = g^{ Σ (r_attr + h_i) }
           = g^{ r + |P| * h_i }

    Then:

        C_star = e(G*, C_hat)
               = e(g, g)^{ (r + |P| h_i) s }

    This C_star is returned to the user together with CT.
    """
    C_hat = ct["C_hat"]
    policy = set(ct["policy_attrs"])
    user_attrs = sk["attrs"]

    # Check policy satisfaction
    if not policy.issubset(user_attrs):
        raise Exception("User attributes do not satisfy policy (fixed scheme).")

    Dj_star = sk["Dj_star"]

    # Compute G* = product of Dj_star[attr] over policy
    G_star = None
    for attr in policy:
        if attr not in Dj_star:
            raise Exception(f"Missing D*_j for attribute '{attr}' in SK.")
        if G_star is None:
            G_star = Dj_star[attr]
        else:
            G_star *= Dj_star[attr]

    # C_star = e(G*, C_hat)
    C_star = pair(G_star, C_hat)
    return C_star, ct
