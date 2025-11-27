# ============================================================
# Token verification (Traceability)
# ============================================================


from charm.toolbox.pairinggroup import ZR 

def verify_token(group, pk, sk):
    """
    Verify the traceability equation:

        PSK_i · P  ==  QID_i + h2(ID_i, QID_i) · Tpub_AA

    This ensures:
      - PSK_i is correctly formed for this ID_i and QID_i
      - QID_i and PSK_i are consistent for the given ID_i
      - The token is bound to the system's α (via Tpub_AA)
      - QID_i is not replaced or reused from another user

    IMPORTANT:
      This does NOT fix the collusion flaw, which stems from the
      per-attribute QID[a] not being bound to ID_i at all.

      Returns True if token is valid; False otherwise.
    """
    ID_i = sk["ID"]
    QID_i = sk["QID_i"]
    PSK_i = sk["PSK_i"]

    P = pk["P"]
    Tpub_AA = pk["Tpub_AA"]

    # Left-hand side: PSK_i * P
    left = PSK_i * P

    # h2(ID_i, QID_i) ∈ ZR
    h2_input = ID_i + group.serialize(QID_i)
    h2_val = group.hash(h2_input, ZR)

    # Right-hand side: QID_i + h2 * Tpub_AA
    right = QID_i + (h2_val * Tpub_AA)

    return left == right
