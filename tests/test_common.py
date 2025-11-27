# tests/test_common.py
# ============================================================
# Shared test runner for both CP-ABE schemes
# ============================================================

from cpabe.flawed.scheme import CollusionFlawedCPABE
from cpabe.fixed.scheme import SensorsCPABEFixedIDBound


def run_common_test(scheme, is_fixed=False):
    print("\n====================================================")
    print(f"   TESTING SCHEME: {scheme.__class__.__name__}")
    print("====================================================")

    # ----- Setup -----
    pk, mk = scheme.setup()

    policy = ["Doctor", "Cardiology"]
    message = b"ECG VERY SECRET DATA"

    # ----- Keygen -----
    if is_fixed:
        skA = scheme.keygen(pk, mk, b"anonA", ["Doctor"])
        skB = scheme.keygen(pk, mk, b"anonB", ["Cardiology"])
    else:
        skA = scheme.keygen(pk, ["Doctor"])
        skB = scheme.keygen(pk, ["Cardiology"])

    # ----- Token Verification -----
    print("\n--- TOKEN VERIFICATION ---")
    print("A valid?:", scheme.verify_token(pk, skA))
    print("B valid?:", scheme.verify_token(pk, skB))

    # ----- Encrypt -----
    ct = scheme.encrypt(pk, message, policy)

    # ----- User A alone -----
    print("\n--- USER A ALONE ---")
    try:
        C_A, ct2 = scheme.partial_decrypt(pk, ct, skA)
        msg = scheme.final_decrypt(pk, skA, C_A, ct2)
        print("❌ WRONG:", msg)
    except Exception as e:
        print("✔ CORRECT:", e)

    # ----- User B alone -----
    print("\n--- USER B ALONE ---")
    try:
        C_B, ct2 = scheme.partial_decrypt(pk, ct, skB)
        msg = scheme.final_decrypt(pk, skB, C_B, ct2)
        print("❌ WRONG:", msg)
    except Exception as e:
        print("✔ CORRECT:", e)

    # ----- Collusion -----
    print("\n--- COLLUSION TEST ---")

    if is_fixed:
        # Identity-bound: collusion must FAIL
        colluders = {
            "ID": skA["ID"],
            "h_i": skA["h_i"],
            "D_prime_star": skA["D_prime_star"],
            "Dj_star": {**skA["Dj_star"], **skB["Dj_star"]},
            "attrs": skA["attrs"] | skB["attrs"],
            "QID_i": skA["QID_i"],
            "PSK_i": skA["PSK_i"],
        }
    else:
        # Vulnerable: collusion must SUCCEED
        colluders = {
            "QID": {**skA["QID"], **skB["QID"]},
            "attrs": skA["attrs"] | skB["attrs"],
            "ID": skA["ID"],
            "QID_i": skA["QID_i"],
            "PSK_i": skA["PSK_i"],
        }

    try:
        C_C, ct2 = scheme.partial_decrypt(pk, ct, colluders)
        msg = scheme.final_decrypt(pk, colluders, C_C, ct2)
        print("COLLUSION RESULT:", msg)
    except Exception as e:
        print("COLLUSION FAILED:", e)
