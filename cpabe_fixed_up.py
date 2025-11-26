# sensors_cpabe_fixed_idbound.py
# ============================================================
# Fixed CP-ABE Scheme with:
#   1) Identity-Bound Decryption Exponents (h_i = H(ID_i))
#   2) Traceability via (QID_i, PSK_i) and public (P, Tpub_AA)
#
# This file combines:
#   - Your original collusion fix (identity-bound D' and D_j)
#   - The traceability mechanism from the paper:
#
#       QID_i  = d_i * P
#       PSK_i  = d_i + h2(ID_i, QID_i) * alpha
#
#   - A token verification equation:
#
#       PSK_i * P  ==  QID_i + h2(ID_i, QID_i) * Tpub_AA
#
# Ciphertext structure and encryption remain unchanged.
# Only the secret key and auxiliary traceability info are extended.
# ============================================================

import hashlib
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction


class SensorsCPABEFixedIDBound:
    """
    Fixed CP-ABE with Identity-Bound Decryption + Traceability.

    ---------------------- Identity Binding ----------------------

    Let ID_i be the user's (anonymous) identity as bytes.
    We derive an identity exponent:

        h_i = H(ID_i) ∈ Z_p

    Original (flawed-style) exponents for the decryption key were:

        D'   = g^(α - r)
        D_j  = g^(r_j)

    where r = Σ r_j over attributes.

    Our FIX modifies them to:

        D'*  = g^(α - r + h_i)
        D*_j = g^(r_j + h_i)

    So there is an extra identity term h_i sprinkled into all
    decryption exponents. Combined with the ciphertext exponent s,
    this yields additional terms in the decryption pairing output
    that depend on h_i.

    Only the legitimate user who *knows* h_i can remove those
    extra factors. If two different users with different h_i
    try to collude, their exponents cannot be combined into one
    clean factor, and decryption fails.

    ------------------------- Traceability ------------------------

    In addition to identity binding, we add traceability components
    for each user:

        d_i   ← random in Z_p
        QID_i = d_i * P        (G1 element)
        h2    = H2(ID_i, QID_i) ∈ Z_p
        PSK_i = d_i + h2 * α   (scalar in Z_p)

    Here P is a public G1 base (from setup), and:

        Tpub_AA = α * P        (public traceability key in G1)

    During token verification, we check:

        PSK_i * P  ==  QID_i + h2 * Tpub_AA

    This binds PSK_i, QID_i, ID_i, and the AA master secret α
    into a single equation, preventing impersonation and
    unauthorized key/token sharing.

    ------------------ Ciphertext & Decryption -------------------

    Ciphertext and encryption remain unchanged coarsely:
        - CT carries (Ce, C_hat, CS, VK1, VK2, policy_attrs)
        - Ce  = KEY * e(g,g)^(α s)
        - C_hat = g^s
        - CS = SymEnc_KEY(M)
        - VK = (g^{h(KEY)}, g^{h(M)})

    Partial decrypt constructs a "C*" term via pairings with D*_j,
    and final decrypt uses D'* and the identity exponent h_i
    to reconstruct the original KEY, then decrypts and checks VK.
    """

    # ============================================================
    # Constructor
    # ============================================================
    def __init__(self, group_name='SS512'):
        # Underlying bilinear pairing group
        self.group = PairingGroup(group_name)

        # Traceability base (public) in G1. Each user's QID_i = d_i * P.
        self.P = self.group.random(G1)

        # Tpub_AA = alpha * P (will be set in setup)
        self.Tpub_AA = None

    # ============================================================
    # Setup: generate system public key and master key
    # ============================================================
    def setup(self):
        """
        Setup() -> (pk, mk)

        Steps:
          1) Choose random g ∈ G1
          2) α ∈ Z_p randomly
          3) Y = e(g,g)^α ∈ GT
          4) Tpub_AA = α * P ∈ G1 for traceability

        Public key:
            pk = { g, Y, P, Tpub_AA }

        Master key:
            mk = { alpha }
        """
        g = self.group.random(G1)
        alpha = self.group.random(ZR)

        # Y = e(g,g)^α
        Y = pair(g, g) ** alpha

        # Traceability public key: Tpub_AA = α P
        self.Tpub_AA = alpha * self.P

        pk = {
            'g': g,
            'Y': Y,
            'P': self.P,
            'Tpub_AA': self.Tpub_AA
        }
        mk = {
            'alpha': alpha
        }
        return pk, mk

    # ============================================================
    # KeyGen: identity-bound + traceability
    # ============================================================
    def keygen(self, pk, mk, user_id_bytes, user_attrs):
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
        g = pk['g']
        P = pk['P']
        alpha = mk['alpha']

        # -------------------
        # 1) identity hash h_i
        # -------------------
        # Hash ID_i into ZR. This is the identity exponent used to
        # augment decryption exponents and block collusion.
        h_i = self.group.hash(user_id_bytes, ZR)

        # -------------------
        # 2) attribute randomness and r sum
        # -------------------
        r_j = {}
        total_r = self.group.init(ZR, 0)
        for attr in user_attrs:
            rv = self.group.random(ZR)
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
        d_i = self.group.random(ZR)

        # QID_i = d_i * P in G1
        QID_i = d_i * P

        # h2 = H2(ID_i, QID_i) in ZR
        # Use ID_i concatenated with serialized QID_i as input
        h2_input = user_id_bytes + self.group.serialize(QID_i)
        h2_val = self.group.hash(h2_input, ZR)

        # PSK_i = d_i + h2 * alpha
        PSK_i = d_i + h2_val * alpha

        # -------------------
        # Put everything into the secret key structure
        # -------------------
        sk = {
            'ID': user_id_bytes,           # identity bytes
            'h_i': h_i,                    # identity exponent
            'D_prime_star': D_prime_star,  # g^(α - r + h_i)
            'Dj_star': Dj_star,            # {attr: g^(r_attr + h_i)}
            'attrs': set(user_attrs),      # attribute set

            # traceability
            'QID_i': QID_i,
            'PSK_i': PSK_i
        }
        return sk

    # ============================================================
    # Token verification (Traceability check)
    # ============================================================
    def verify_token(self, pk, sk):
        """
        Verify the user's traceability token:

            PSK_i * P  ==  QID_i + h2(ID_i, QID_i) * Tpub_AA

        This ensures that:
          - PSK_i is correctly formed for this ID_i and QID_i
          - The token is tied to the system's α (via Tpub_AA)
          - QID_i is not replaced or reused from another user

        Returns True if token is valid; False otherwise.
        """
        ID_i = sk['ID']
        QID_i = sk['QID_i']
        PSK_i = sk['PSK_i']
        P = pk['P']
        Tpub_AA = pk['Tpub_AA']

        # Left-hand side: PSK_i * P
        left = PSK_i * P

        # h2(ID_i, QID_i) ∈ ZR
        h2_input = ID_i + self.group.serialize(QID_i)
        h2_val = self.group.hash(h2_input, ZR)

        # Right-hand side: QID_i + h2 * Tpub_AA
        right = QID_i + (h2_val * Tpub_AA)

        return left == right

    # ============================================================
    # Helper: KDF from GT -> bytes
    # ============================================================
    def _kdf(self, K_gt):
        """
        Derive a symmetric key from a GT element using SHA-256 over its
        serialized byte representation.
        """
        K_bytes = self.group.serialize(K_gt)
        return hashlib.sha256(K_bytes).digest()

    def _hash_to_ZR(self, data):
        """
        Safely hash arbitrary data (bytes or group element) into ZR.
        """
        if isinstance(data, bytes):
            raw = data
        else:
            raw = self.group.serialize(data)
        return self.group.hash(raw, ZR)

    # ============================================================
    # Encrypt: same structure as before (no change)
    # ============================================================
    def encrypt(self, pk, message_bytes, policy_attrs):
        """
        Encrypt(PK, M, P) -> CT

        Input:
          - pk: public key
          - message_bytes: plaintext M
          - policy_attrs: list/set of attributes defining an AND-policy P

        Steps:
          1) Choose s ∈ Z_p randomly
          2) Choose KEY ∈ GT randomly
          3) Ce = KEY * Y^s
          4) C_hat = g^s
          5) CS = Enc_KEY(M)
          6) VK = (g^{h(KEY)}, g^{h(M)})

        Output:
          CT = { Ce, C_hat, CS, VK1, VK2, policy_attrs }
        """
        g = pk['g']
        Y = pk['Y']
        group = self.group

        # random s in Z_p
        s = group.random(ZR)

        # random KEY in GT
        KEY = group.random(GT)

        # Ce = KEY * (Y^s) = KEY * e(g,g)^(α s)
        Ce = KEY * (Y ** s)

        # C_hat = g^s
        C_hat = g ** s

        # Symmetric encryption using KEY
        sym_key = self._kdf(KEY)
        sym = SymmetricCryptoAbstraction(sym_key)
        CS = sym.encrypt(message_bytes)

        # Verification tag
        h_key = self._hash_to_ZR(KEY)
        h_msg = self._hash_to_ZR(message_bytes)
        VK1 = g ** h_key
        VK2 = g ** h_msg

        ct = {
            'Ce': Ce,
            'C_hat': C_hat,
            'CS': CS,
            'VK1': VK1,
            'VK2': VK2,
            'policy_attrs': list(policy_attrs)
        }
        return ct

    # ============================================================
    # Partial decrypt (AC/server side)
    # ============================================================
    def partial_decrypt(self, pk, ct, sk):
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
        C_hat = ct['C_hat']
        policy = set(ct['policy_attrs'])
        user_attrs = sk['attrs']

        # Check policy satisfaction
        if not policy.issubset(user_attrs):
            raise Exception("User attributes do not satisfy policy (fixed scheme).")

        Dj_star = sk['Dj_star']

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

    # ============================================================
    # Final decrypt (User side)
    # ============================================================
    def final_decrypt(self, pk, sk, C_star, ct):
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
        g = pk['g']
        h_i = sk['h_i']
        D_prime_star = sk['D_prime_star']

        Ce = ct['Ce']
        C_hat = ct['C_hat']
        CS = ct['CS']
        VK1 = ct['VK1']
        VK2 = ct['VK2']
        policy = ct['policy_attrs']
        k = len(policy)  # |P|

        # 1) Compute KEY0* = Ce / ( e(C_hat, D'*) * C* )
        denom = pair(C_hat, D_prime_star) * C_star
        KEY0_star = Ce / denom

        # 2) Compute φ_i = e(g^{h_i}, C_hat) = e(g, g)^{h_i s}
        g_hi = g ** h_i
        phi_i = pair(g_hi, C_hat)

        # 3) Recover KEY = KEY0* * φ_i^{k+1}
        KEY = KEY0_star * (phi_i ** (k + 1))

        # 4) Symmetric decrypt with KEY
        sym_key = self._kdf(KEY)
        sym = SymmetricCryptoAbstraction(sym_key)
        M_bytes = sym.decrypt(CS)

        # 5) Verify VK
        h_key = self._hash_to_ZR(KEY)
        h_msg = self._hash_to_ZR(M_bytes)

        VK1_check = g ** h_key
        VK2_check = g ** h_msg

        if VK1 != VK1_check or VK2 != VK2_check:
            raise Exception("Verification failed (fixed scheme): VK mismatch.")

        return M_bytes
