from cpabe_original import (
    setup,
    keygen,
    encrypt,
    decrypt,
    colluding_decrypt,
)


def main():
    # System setup
    pk, msk = setup()
    print("Public params:", pk)
    print("Master key:", msk.secret, "\n")

    # Policy and users
    policy = {"doctor", "mayo_clinic"}

    alice_attrs = {"doctor"}          # Alice has 1 attribute
    bob_attrs = {"mayo_clinic"}       # Bob has the other attribute

    # Generate keys
    sk_alice = keygen(msk, alice_attrs)
    sk_bob = keygen(msk, bob_attrs)

    # Encrypt
    message = "Medical: MRI scan"
    ct = encrypt(pk, policy, message)
    print("Ciphertext created with policy:", ct.policy)

    # Alice cannot decrypt alone
    print("\n=== Alice tries ===")
    try:
        print(decrypt(ct, sk_alice))
    except Exception as e:
        print("Alice failed:", e)

    # Bob cannot decrypt alone
    print("\n=== Bob tries ===")
    try:
        print(decrypt(ct, sk_bob))
    except Exception as e:
        print("Bob failed:", e)

    # Collusion (original flaw) — SUCCESS
    print("\n=== Alice + Bob collude ===")
    try:
        print("[SUCCESS] Collusion decrypted →", colluding_decrypt(ct, [sk_alice, sk_bob]))
    except Exception as e:
        print("Collusion failed:", e)


if __name__ == "__main__":
    main()
