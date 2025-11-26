# test_common.py
# ============================================================
# Unified test file for:
#
#   1) CollusionFlawedCPABE
#   2) SensorsCPABEFixedIDBound
#
# This script performs full evaluation for BOTH schemes:
#
#   ✔ Setup
#   ✔ KeyGen
#   ✔ Token verification
#   ✔ Encryption
#   ✔ A alone decryption
#   ✔ B alone decryption
#   ✔ Collusion test (A + B merging keys)
#
# Expected results:
#
#   --- Flawed scheme ---
#   A alone: FAIL (correct)
#   B alone: FAIL (correct)
#   A+B collusion: SUCCESS (flaw)
#
#   --- Fixed scheme ---
#   A alone: FAIL (correct)
#   B alone: FAIL (correct)
#   A+B collusion: FAIL (correct)
# ============================================================

from cpabe_flawed_up import CollusionFlawedCPABE
from cpabe_fixed_up import SensorsCPABEFixedIDBound


def run_common_test(scheme, is_fixed=False):
    print("\n====================================================")
    print(f"   TESTING SCHEME: {scheme.__class__.__name__}")
    print("====================================================")

    # ------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------
    print("\n--- SETUP ---")
    pk, mk = scheme.setup()
    print("PK and MK generated.")

    # Test policy and message
    policy = ["Doctor", "Cardiology"]
    message = b"ECG VERY SECRET DATA"

    # ------------------------------------------------------------
    # Key generation for two users
    # ------------------------------------------------------------
    print("\n--- KEY GENERATION ---")

    if is_fixed:
        # fixed scheme requires explicit ID_i in bytes
        print("Generating SK for User A (ID: anonA, attrs: Doctor)...")
        skA = scheme.keygen(pk, mk, b"anonA", ["Doctor"])

        print("Generating SK for User B (ID: anonB, attrs: Cardiology)...")
        skB = scheme.keygen(pk, mk, b"anonB", ["Cardiology"])
    else:
        # flawed scheme identity is optional; keygen derives it
        print("Generating SK for User A (attrs: Doctor)...")
        skA = scheme.keygen(pk, ["Doctor"])

        print("Generating SK for User B (attrs: Cardiology)...")
        skB = scheme.keygen(pk, ["Cardiology"])

    # ------------------------------------------------------------
    # Token verification
    # ------------------------------------------------------------
    print("\n--- TOKEN VERIFICATION ---")
    validA = scheme.verify_token(pk, skA)
    validB = scheme.verify_token(pk, skB)
    print(f"Token A valid?: {validA}")
    print(f"Token B valid?: {validB}")

    # Both tokens should be valid for both schemes
    if not validA or not validB:
        print("[ERROR] Token verification failed unexpectedly.")
    else:
        print("[OK] Both tokens verified successfully.")

    # ------------------------------------------------------------
    # Encryption
    # ------------------------------------------------------------
    print("\n--- ENCRYPTION ---")
    print(f"Encrypting message under policy: {policy} ...")
    ct = scheme.encrypt(pk, message, policy)
    print("Ciphertext generated.")

    # ------------------------------------------------------------
    # User A alone attempt
    # ------------------------------------------------------------
    print("\n--- USER A ALONE ---")
    try:
        C_A, ct2 = scheme.partial_decrypt(pk, ct, skA)
        msg_A = scheme.final_decrypt(pk, skA, C_A, ct2)
        print("❌ WRONG: User A decrypted message:", msg_A)
    except Exception as e:
        print("✔ CORRECT: User A denied:", e)

    # ------------------------------------------------------------
    # User B alone attempt
    # ------------------------------------------------------------
    print("\n--- USER B ALONE ---")
    try:
        C_B, ct2 = scheme.partial_decrypt(pk, ct, skB)
        msg_B = scheme.final_decrypt(pk, skB, C_B, ct2)
        print("❌ WRONG: User B decrypted message:", msg_B)
    except Exception as e:
        print("✔ CORRECT: User B denied:", e)

    # ------------------------------------------------------------
    # Collusion attempt (A + B pooling keys)
    # ------------------------------------------------------------
    print("\n--- COLLUSION TEST (User A + User B) ---")

    if is_fixed:
        # FIXED SCHEME: identity-bound keys prevent mixing Dj*

        # Merge ONLY Dj_star (identity-bound attribute keys)
        colludedDj = {}
        colludedDj.update(skA["Dj_star"])
        colludedDj.update(skB["Dj_star"])

        # Build fake colluder key using A's identity
        fake_sk = {
            "ID": skA["ID"],                   # pretending to be A
            "h_i": skA["h_i"],                 # using h_i of A
            "D_prime_star": skA["D_prime_star"],
            "Dj_star": colludedDj,
            "attrs": skA["attrs"].union(skB["attrs"]),

            # Traceability values - keep from A (must be consistent)
            "QID_i": skA["QID_i"],
            "PSK_i": skA["PSK_i"]
        }
    else:
        # FLAWED SCHEME: attribute pooling trivial

        # Merge QID maps
        colludedQID = {}
        colludedQID.update(skA["QID"])
        colludedQID.update(skB["QID"])

        fake_sk = {
            "QID": colludedQID,
            "attrs": skA["attrs"].union(skB["attrs"]),

            # Any token, not relevant to flaw
            "ID": skA["ID"],
            "QID_i": skA["QID_i"],
            "PSK_i": skA["PSK_i"]
        }

    # Try collusion
    try:
        C_C, ct2 = scheme.partial_decrypt(pk, ct, fake_sk)
        msg_C = scheme.final_decrypt(pk, fake_sk, C_C, ct2)

        if is_fixed:
            print("🟥 COLLUSION SHOULD FAIL BUT SUCCEEDED:", msg_C)
        else:
            print("🟩 COLLUSION SUCCESS (EXPECTED IN FLAWED SCHEME):", msg_C)

    except Exception as e:
        if is_fixed:
            print("🟩 COLLUSION FAILED AS EXPECTED:", e)
        else:
            print("🟥 COLLUSION SHOULD SUCCEED BUT FAILED:", e)


# ============================================================
# Main runner
# ============================================================
if __name__ == "__main__":

    print("\n\n====================================================")
    print("RUNNING TEST FOR FLAWED SCHEME")
    print("====================================================")
    run_common_test(CollusionFlawedCPABE(), is_fixed=False)

    print("\n\n====================================================")
    print("RUNNING TEST FOR FIXED SCHEME")
    print("====================================================")
    run_common_test(SensorsCPABEFixedIDBound(), is_fixed=True)
