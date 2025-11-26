# cpabe_flawed.py
# ============================================================
# Deliberately FLAWED CP-ABE-like scheme for demonstrating
# attribute-pooling collusion attacks.
#
# 1) Core Design (Flawed):
#    - Each attribute a has a master weight w[a] ∈ Z_p known to AA.
#    - User key for attribute a: QID[a] = g^{w[a]}  (NO per-user randomness).
#    - Ciphertext for policy P embeds S_w = sum_{a in P} w[a] in exponent.
#    - AC/server reconstructs e(g,g)^{S_w·s} using user QID[a].
#
#    If two different users A and B each hold some attributes in P,
#    they can POOL their QID[a] values to reconstruct G = g^{S_w} and
#    thus the same decryption exponent that a single legitimate user would have.
#
#    → This is the **collusion flaw**: no identity binding, only attribute-based.
#
# 2) Traceability Extension (Correct but orthogonal):
#    - We add a per-user identity ID_i (bytes).
#    - We add traceability components:
#         d_i   ← random in Z_p
#         QID_i = d_i · P
#         h2    = H2(ID_i, QID_i) ∈ Z_p
#         PSK_i = d_i + h2 · α
#
#    - System has public (P, Tpub_AA), where Tpub_AA = α · P.
#
#    - Token verification equation:
#         PSK_i · P  ==  QID_i + h2(ID_i, QID_i) · Tpub_AA
#
#    This ensures that each user's SK can be traced back
#    and that QID_i, PSK_i are consistent for that identity.
#
#    NOTE: Traceability does NOT fix the collusion flaw itself.
#    The "flawed" part is that attribute keys QID[a] are not
#    bound to user identities, so users can still pool attributes.
# ============================================================

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
import hashlib


class CollusionFlawedCPABE:
    """
    Deliberately flawed CP-ABE-like construction to show attribute pooling:

    - Each attribute a has a master weight w[a].
    - If policy P = {a1, ..., ak}, we embed S_w = sum w[a_i] into the
      ciphertext exponent.
    - A user's secret key contains QID[a] = g^{w[a]} for each attribute
      they hold.
    - A single user with all attributes in P can reconstruct G = g^{S_w}
      and thus e(g,g)^{S_w · s} needed for decryption.

    BUT if two users A and B each hold a subset of attributes in P,
    they can combine their QID[a] values (attribute pooling) to build
    the full product G = g^{S_w}, and decrypt even though neither user
    satisfies the policy alone.

    We additionally add traceability (QID_i, PSK_i, ID_i) so that leaked
    keys can be traced, but this does NOT fix the central collusion flaw.
    """

    # ============================================================
    # Constructor
    # ============================================================
    def __init__(self, group_name='SS512'):
        self.group = PairingGroup(group_name)

        # Master key structure stored after setup().
        # mk = { 'alpha': alpha, 'w': {attr: w_attr} }
        self.mk = None

        # Traceability public base P in G1
        self.P = self.group.random(G1)
        # Tpub_AA = alpha · P will be set in setup()
        self.Tpub_AA = None

    # ============================================================
    # Setup
    # ============================================================
    def setup(self):
        """
        Setup() -> (pk, mk)

        Steps:
          1) Choose generator g ∈ G1
          2) Choose α ∈ Z_p
          3) Y = e(g,g)^α ∈ GT
          4) Tpub_AA = α · P ∈ G1  (traceability component)

        Public key:
            pk = { g, Y, P, Tpub_AA }

        Master key:
            mk = { alpha, w }  where w is an initially empty map
                                  attr -> w[attr] in Z_p
        """
        g = self.group.random(G1)
        alpha = self.group.random(ZR)
        Y = pair(g, g) ** alpha

        # Traceability public key part
        self.Tpub_AA = alpha * self.P

        pk = {
            'g': g,
            'Y': Y,
            'P': self.P,
            'Tpub_AA': self.Tpub_AA
        }
        mk = {
            'alpha': alpha,
            'w': {}   # attribute -> weight w[a]
        }

        self.mk = mk
        return pk, mk

    # ============================================================
    # Helpers
    # ============================================================
    def _kdf(self, K_gt):
        """
        Derive a symmetric key (bytes) from a GT element via SHA-256.
        """
        K_bytes = self.group.serialize(K_gt)
        return hashlib.sha256(K_bytes).digest()

    def _hash_to_ZR(self, data):
        """
        Hash arbitrary data (bytes or group element) into ZR.
        """
        if isinstance(data, bytes):
            raw = data
        else:
            raw = self.group.serialize(data)
        return self.group.hash(raw, ZR)

    # ============================================================
    # KeyGen  (Flawed per-attribute scheme + traceability)
    # ============================================================
    def keygen(self, pk, user_attrs, user_id_bytes=None):
        """
        KeyGen(pk, user_attrs, user_id_bytes=None) -> sk

        FLAWED attribute side:
          For each attribute a ∈ user_attrs:
            if w[a] not set:
               w[a] randomly in Z_p
            QID[a] = g^{w[a]}

          No per-user randomness here, only per-attribute weight.
          QID[a] is the same for any user who has attribute a.

        This is the essence of the collusion flaw: attribute powers
        can be pooled between users.

        Traceability side:
          We also create an identity ID_i (user_id_bytes), if not provided
          we derive one from the attribute list:

              ID_i = b"user|" + sorted(attribute names)...

          Then:
              d_i   ← random in Z_p
              QID_i = d_i · P
              h2    = H2(ID_i, QID_i) ∈ Z_p
              PSK_i = d_i + h2 · α

        Output:
          sk = {
            'QID':   {attr: g^{w[attr]}},
            'attrs': set(user_attrs),
            'ID':    ID_i,
            'QID_i': QID_i,
            'PSK_i': PSK_i
          }
        """
        if self.mk is None:
            raise Exception("Run setup() first so self.mk is initialized.")

        g = pk['g']
        w_map = self.mk['w']
        alpha = self.mk['alpha']
        P = pk['P']

        # 1) Per-attribute flawed part: QID[a] = g^{w[a]}
        QID = {}
        for attr in user_attrs:
            if attr not in w_map:
                w_map[attr] = self.group.random(ZR)
            QID[attr] = g ** w_map[attr]

        # 2) Identity for this user: either provided or derived
        if user_id_bytes is None:
            # Derive a pseudo-identity from sorted attributes
            sorted_attrs = sorted(list(user_attrs))
            user_id_bytes = b"user|" + "|".join(sorted_attrs).encode('utf-8')

        # 3) Traceability: QID_i, PSK_i
        # Choose per-user randomness d_i
        d_i = self.group.random(ZR)

        # QID_i = d_i * P
        QID_i = d_i * P

        # h2 = H2(ID_i, QID_i)
        h2_input = user_id_bytes + self.group.serialize(QID_i)
        h2_val = self.group.hash(h2_input, ZR)

        # PSK_i = d_i + h2 * alpha
        PSK_i = d_i + h2_val * alpha

        # Combine into SK
        sk = {
            'QID': QID,                   # per-attribute components
            'attrs': set(user_attrs),     # attribute set
            'ID': user_id_bytes,          # identity bytes
            'QID_i': QID_i,               # traceability tag
            'PSK_i': PSK_i                # pseudo secret key
        }
        return sk

    # ============================================================
    # Token verification (Traceability)
    # ============================================================
    def verify_token(self, pk, sk):
        """
        Verify the traceability equation:

            PSK_i · P  ==  QID_i + h2(ID_i, QID_i) · Tpub_AA

        This ensures:
          - QID_i and PSK_i are consistent for the given ID_i
          - The token is bound to the system's α (via Tpub_AA)

        IMPORTANT:
          This does NOT fix the collusion flaw, which stems from the
          per-attribute QID[a] not being bound to ID_i at all.
        """
        ID_i = sk['ID']
        QID_i = sk['QID_i']
        PSK_i = sk['PSK_i']

        P = pk['P']
        Tpub_AA = pk['Tpub_AA']

        # Left-hand side: PSK_i * P
        left = PSK_i * P

        # h2(ID_i, QID_i)
        h2_input = ID_i + self.group.serialize(QID_i)
        h2_val = self.group.hash(h2_input, ZR)

        # Right-hand side: QID_i + h2 * Tpub_AA
        right = QID_i + (h2_val * Tpub_AA)

        return left == right

    # ============================================================
    # Encrypt
    # ============================================================
    def encrypt(self, pk, message_bytes, policy_attrs):
        """
        Encrypt(pk, M, P) -> CT

        P = policy_attrs (AND-policy).
        Let S_w = sum_{a in P} w[a].

        Steps:
          1) Ensure w[a] exists for all a in P (choose random if not).
          2) Compute S_w = Σ w[a].
          3) Choose s ∈ Z_p, KEY ∈ GT randomly.
          4) Ce   = KEY * e(g,g)^{S_w·s}
          5) C_hat= g^s
          6) CS   = Enc_KEY(M)
          7) VK   = (g^{h(KEY)}, g^{h(M)})

        CT = { Ce, C_hat, CS, VK1, VK2, policy_attrs }
        """
        if self.mk is None:
            raise Exception("Run setup() first so self.mk is initialized.")

        g = pk['g']
        Y = pk['Y']  # not strictly needed, but kept for structural analogy
        group = self.group
        w_map = self.mk['w']

        # 1) Ensure w[a] defined, compute S_w
        S_w = group.init(ZR, 0)
        for attr in policy_attrs:
            if attr not in w_map:
                w_map[attr] = group.random(ZR)
            S_w += w_map[attr]

        # 2) Choose s, KEY
        s = group.random(ZR)
        KEY = group.random(GT)

        # 3) Ce = KEY * e(g,g)^{S_w·s}
        Ce = KEY * (pair(g, g) ** (S_w * s))

        # 4) C_hat = g^s
        C_hat = g ** s

        # 5) Symmetric encryption
        sym_key = self._kdf(KEY)
        sym = SymmetricCryptoAbstraction(sym_key)
        CS = sym.encrypt(message_bytes)

        # 6) Verification tag
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
    # Partial decrypt (AC / Server side)
    # ============================================================
    def partial_decrypt(self, pk, ct, sk):
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
        C_hat = ct['C_hat']
        policy = set(ct['policy_attrs'])

        user_attrs = sk['attrs']
        if not policy.issubset(user_attrs):
            raise Exception("User attributes do not satisfy policy (flawed scheme).")

        QID = sk['QID']

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

    # ============================================================
    # Final decrypt (User side)
    # ============================================================
    def final_decrypt(self, pk, sk, C_dec, ct):
        """
        final_decrypt_flawed(pk, SK, C_dec, CT) -> M

        KEY = Ce / C_dec, because:

           Ce   = KEY * e(g,g)^{S_w·s}
           C_dec= e(g,g)^{S_w·s}

        So:

           KEY = Ce / C_dec

        Then:

           M   = Dec_KEY(CS)

        Finally verify VK = (g^{h(KEY)}, g^{h(M)}).
        """
        g = pk['g']

        Ce = ct['Ce']
        CS = ct['CS']
        VK1 = ct['VK1']
        VK2 = ct['VK2']

        # 1) Recover KEY
        KEY = Ce / C_dec  # GT element

        # 2) Symmetric decryption
        sym_key = self._kdf(KEY)
        sym = SymmetricCryptoAbstraction(sym_key)
        M_bytes = sym.decrypt(CS)

        # 3) Verification
        h_key = self._hash_to_ZR(KEY)
        h_msg = self._hash_to_ZR(M_bytes)
        VK1_chk = g ** h_key
        VK2_chk = g ** h_msg

        if VK1 != VK1_chk or VK2 != VK2_chk:
            raise Exception("Verification failed (flawed scheme).")

        return M_bytes
