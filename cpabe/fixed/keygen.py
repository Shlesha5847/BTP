from charm.toolbox.pairinggroup import ZR


# ============================================================
# KeyGen: identity-bound + traceability
# ============================================================
def keygen(group, pk, mk, user_id_bytes, user_attrs):
    """
    KeyGen_fixed(PK, MK, ID_i, S) -> SK

    Inputs:
      - pk: public key from setup()
      - mk: master key from setup()
      - user_id_bytes: ID_i (anonymous identity) in bytes
      - user_attrs:  attribute set S for this user

    Steps:
      (Identity binding)
        1) h_i = H(ID_i) ∈ Z_p
        2) For each attribute a ∈ S:
              r_a ← random in Z_p
           Let r = Σ_a r_a
        3) D'*   = g^(α - r + h_i)
           D*_a  = g^(r_a + h_i)

      (Traceability)
        4) d_i ← random in Z_p
        5) QID_i = d_i * P
        6) h2    = H2(ID_i, QID_i) ∈ Z_p
        7) PSK_i = d_i + h2 * α

    Output secret key:
        sk = {
          'ID': user_id_bytes,
          'h_i': h_i,
          'D_prime_star': D'*,
          'Dj_star': { attr: D*_attr },
          'attrs': S,
          'QID_i': QID_i,
          'PSK_i': PSK_i
        }
    """
    g = pk["g"]
    P = pk["P"]
    alpha = mk["alpha"]

    # -------------------
    # 1) identity hash h_i
    # -------------------
    # Hash ID_i into ZR. This is the identity exponent used to
    # augment decryption exponents and block collusion.
    h_i = group.hash(user_id_bytes, ZR)

    # -------------------
    # 2) attribute randomness and r sum
    # -------------------
    r_j = {}
    total_r = group.init(ZR, 0)
    for attr in user_attrs:
        rv = group.random(ZR)
        r_j[attr] = rv
        total_r += rv

    # -------------------
    # 3) identity-bound exponents
    # -------------------
    # D'*  = g^(α - r + h_i)
    D_prime_star = g ** (alpha - total_r + h_i)

    # D*_a = g^(r_a + h_i) for each attribute
    Dj_star = {attr: g ** (r_j[attr] + h_i) for attr in r_j.keys()}

    # -------------------
    # 4)–7) Traceability (QID_i, PSK_i)
    # -------------------
    # Choose per-user randomness d_i
    d_i = group.random(ZR)

    # QID_i = d_i * P in G1
    QID_i = d_i * P

    # h2 = H2(ID_i, QID_i) in ZR
    # Use ID_i concatenated with serialized QID_i as input
    h2_input = user_id_bytes + group.serialize(QID_i)
    h2_val = group.hash(h2_input, ZR)

    # PSK_i = d_i + h2 * alpha
    PSK_i = d_i + h2_val * alpha

    # -------------------
    # Put everything into the secret key structure
    # -------------------
    sk = {
        "ID": user_id_bytes,  # identity bytes
        "h_i": h_i,  # identity exponent
        "D_prime_star": D_prime_star,  # g^(α - r + h_i)
        "Dj_star": Dj_star,  # {attr: g^(r_attr + h_i)}
        "attrs": set(user_attrs),  # attribute set
        # traceability
        "QID_i": QID_i,
        "PSK_i": PSK_i,
    }
    return sk
