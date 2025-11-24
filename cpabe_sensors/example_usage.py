from cpabe_initial import (
    setup,
    keygen,
    encrypt,
    decrypt,
    colluding_decrypt,
)


def main():
    # --- 1. System setup ---
    pk, msk = setup()
    print("Public params:", pk)
    print("Master key (KEEP SECRET):", msk.secret, "\n")

    # --- 2. Define attributes & users ---
    # Policy: user must have ALL of these attributes (AND policy)
    policy = {"doctor", "mayo_clinic", "neurology"}

    attrs_alice = {"doctor", "mayo_clinic", "neurology"}  # satisfies policy
    attrs_bob = {"nurse", "mayo_clinic", "neurology"}     # does NOT satisfy policy

    # --- 3. Generate keys (identity-bound) ---
    sk_alice = keygen(msk, user_id="alice@example.com", attributes=attrs_alice)
    sk_bob = keygen(msk, user_id="bob@example.com", attributes=attrs_bob)

    print("Alice's attributes :", sk_alice.attributes)
    print("Bob's attributes    :", sk_bob.attributes, "\n")

    # --- 4. Encrypt a message under the policy, bound to Alice's ID ---
    message = "Patient record: MRI results..."
    ct = encrypt(
        pk,
        policy=policy,
        message=message,
        bound_user="alice@example.com",   # ID-binding (Sensors-style fix)
    )

    print("Ciphertext created with policy:", ct.policy)
    print("Bound user ID:", ct.bound_user)
    print("Nonce:", ct.nonce, "\n")

    # --- 5. Valid decryption by Alice (should succeed) ---
    print("=== Alice tries to decrypt ===")
    try:
        decrypted = decrypt(ct, sk_alice)
        print("[OK] Alice decrypted:", decrypted, "\n")
    except Exception as e:
        print("[ERR] Alice decryption failed:", e, "\n")

    # --- 6. Bob tries to decrypt (should FAIL: wrong ID + attributes) ---
    print("=== Bob tries to decrypt ===")
    try:
        decrypted = decrypt(ct, sk_bob)
        print("[BUG] Bob should NOT decrypt, but got:", decrypted, "\n")
    except Exception as e:
        print("[OK] Bob decryption blocked:", e, "\n")

    # --- 7. Collusion attempt: Alice + Bob combine keys (should FAIL) ---
    print("=== Collusion attempt: Alice + Bob ===")
    try:
        decrypted = colluding_decrypt(ct, [sk_alice, sk_bob])
        print("[BUG] Colluding decryption succeeded:", decrypted, "\n")
    except Exception as e:
        print("[OK] Collusion prevented:", e, "\n")


if __name__ == "__main__":
    main()
