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
import hashlib
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair


from cpabe.flawed.keygen import keygen as keygen_mod
from cpabe.flawed.encrypt import encrypt as encrypt_mod
from cpabe.flawed.decrypt_partial import partial_decrypt as partial_mod
from cpabe.flawed.decrypt_final import final_decrypt as final_mod

from cpabe.utils.verification import verify_token as verify_token_mod


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
    def __init__(self, group_name="SS512"):
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

        pk = {"g": g, "Y": Y, "P": self.P, "Tpub_AA": self.Tpub_AA}
        mk = {
            "alpha": alpha,
            "w": {},  # attribute -> weight w[a]
        }

        self.mk = mk
        return pk, mk

    # ------------------------------------------------------------
    # KeyGen (delegated)
    # ------------------------------------------------------------
    def keygen(self, pk, user_attrs):
        return keygen_mod(self.group, pk, self.mk, user_attrs)

    # ------------------------------------------------------------
    # Verify Token (delegated to utils)
    # ------------------------------------------------------------
    def verify_token(self, pk, sk):
        return verify_token_mod(self.group, pk, sk)

    # ------------------------------------------------------------
    # Encryption (delegated)
    # ------------------------------------------------------------
    def encrypt(self, pk, message_bytes, policy_attrs):
        return encrypt_mod(self.group, pk, self.mk, message_bytes, policy_attrs)

    # ------------------------------------------------------------
    # Partial Decrypt (delegated)
    # ------------------------------------------------------------
    def partial_decrypt(self, pk, ct, sk):
        return partial_mod(self.group, pk, ct, sk)

    # ------------------------------------------------------------
    # Final Decrypt (delegated)
    # ------------------------------------------------------------
    def final_decrypt(self, pk, sk, C_dec, ct):
        return final_mod(self.group, pk, sk, C_dec, ct)
