# demo/run_demo.py
# ============================================================
# DEMO:
# 1) Legitimate user with full attributes can decrypt.
# 2) Two users A & B try to collude -> AC detects mismatch and blocks.
# ============================================================

from authorities.TA import TraceAuthority
from authorities.AA import AttributeAuthority
from servers.ACServer import AccessControlServer
from client.User import UserClient
from crypto.Encrypt import Encryptor


def legit_demo():
    print("\n=== DEMO 1: Legitimate decryption (single user) ===\n")

    # ---------- Setup ----------
    U = ["Doctor", "Nurse", "Cardiology"]
    aa = AttributeAuthority(U)
    ta = TraceAuthority()
    ac = AccessControlServer(aa)

    # ---------- Register one user with full attributes ----------
    RID = "RealID-FULL"
    ID_i = ta.register(RID, "FullUser", "2025")
    user_attrs = ["Doctor", "Cardiology"]
    SK = aa.keygen_with_trace(ID_i, user_attrs)
    user_id = "full_user"

    ac.register_user_from_aa(user_id, ID_i, SK["QID_i"], SK["S"])
    user = UserClient(user_id, ID_i, SK, aa)

    # ---------- Encrypt record ----------
    encryptor = Encryptor(aa.PK)
    message = b"Patient ECG: Normal sinus rhythm."
    AS = ["Doctor", "Cardiology"]
    CT0 = encryptor.encrypt(message, AS)
    ac.store_ciphertext("rec_full", CT0)

    # ---------- Token + verify ----------
    token = user.create_token()
    ok = ac.verify_token(user_id, token["PSK_IDi"], token["ID_i"])
    print("[AC] Token verified:", ok)

    # ---------- AC partial decrypt ----------
    C, CTX = ac.partial_decrypt(user_id, "rec_full", SK)
    print("[AC] Partial decrypt OK:", C)

    # ---------- User final decrypt ----------
    recovered = user.final_decrypt(C, CTX)
    print("[User] Decrypted message:", recovered.decode("utf-8"))
    print("\n=== END DEMO 1 ===\n")


def collusion_demo():
    print("\n=== DEMO 2: Collusion attempt (FIXED, collusion blocked) ===\n")

    # ---------- Setup ----------
    U = ["Doctor", "Nurse", "Cardiology"]
    aa = AttributeAuthority(U)
    ta = TraceAuthority()
    ac = AccessControlServer(aa)

    # ---------- Encrypt record requiring BOTH Doctor & Cardiology ----------
    encryptor = Encryptor(aa.PK)
    message = b"SENSITIVE: Only Doctor & Cardiology specialist should see this."
    AS = ["Doctor", "Cardiology"]
    CT0 = encryptor.encrypt(message, AS)
    ac.store_ciphertext("rec_collude", CT0)
    print("[Encryptor] Stored ciphertext with policy:", AS)

    # ---------- USER A (Doctor only) ----------
    RID_A = "RealID-A"
    ID_A = ta.register(RID_A, "UserA", "2025")
    attrs_A = ["Doctor"]
    SK_A = aa.keygen_with_trace(ID_A, attrs_A)
    userA_id = "userA"
    ac.register_user_from_aa(userA_id, ID_A, SK_A["QID_i"], SK_A["S"])
    userA = UserClient(userA_id, ID_A, SK_A, aa)

    # ---------- USER B (Cardiology only) ----------
    RID_B = "RealID-B"
    ID_B = ta.register(RID_B, "UserB", "2025")
    attrs_B = ["Cardiology"]
    SK_B = aa.keygen_with_trace(ID_B, attrs_B)
    userB_id = "userB"
    ac.register_user_from_aa(userB_id, ID_B, SK_B["QID_i"], SK_B["S"])
    userB = UserClient(userB_id, ID_B, SK_B, aa)

    # ---------- A ALONE CANNOT DECRYPT ----------
    print("\n[TEST] User A alone tries to decrypt:")
    try:
        C_A, CTX_A = ac.partial_decrypt(userA_id, "rec_collude", SK_A)
        recovered_A = userA.final_decrypt(C_A, CTX_A)
        print("  !! Unexpectedly decrypted !! ->", recovered_A.decode())
    except Exception as e:
        print("  Correct: User A cannot decrypt. Reason:", e)

    # ---------- B ALONE CANNOT DECRYPT ----------
    print("\n[TEST] User B alone tries to decrypt:")
    try:
        C_B, CTX_B = ac.partial_decrypt(userB_id, "rec_collude", SK_B)
        recovered_B = userB.final_decrypt(C_B, CTX_B)
        print("  !! Unexpectedly decrypted !! ->", recovered_B.decode())
    except Exception as e:
        print("  Correct: User B cannot decrypt. Reason:", e)

    # ---------- COLLUSION ATTEMPT ----------
    print("\n[ATTACK] User A and User B collude and combine their attributes.")

    colluded_S = SK_A["S"] | SK_B["S"]
    colluded_attr_keys = {}
    colluded_attr_keys.update(SK_A["attr_keys"])
    colluded_attr_keys.update(SK_B["attr_keys"])

    SK_colluded = {
        "S": colluded_S,
        "PSK_IDi": SK_A["PSK_IDi"],   # attacker reuses A's identity fields
        "QID_i": SK_A["QID_i"],
        "attr_keys": colluded_attr_keys,
    }

    print("  Colluded attribute set =", colluded_S)

    # AC now checks S_from_SK against S_recorded[userA_id], so this must fail
    try:
        C_coll, CTX_coll = ac.partial_decrypt(userA_id, "rec_collude", SK_colluded)
        print("  !! ERROR: Collusion unexpectedly passed. !!")
        recovered = userA.final_decrypt(C_coll, CTX_coll)
        print("  Decrypted:", recovered.decode())
    except Exception as e:
        print("  ✅ Collusion blocked by AC. Reason:", e)

    print("\n=== END DEMO 2 ===\n")


if __name__ == "__main__":
    legit_demo()
    collusion_demo()
