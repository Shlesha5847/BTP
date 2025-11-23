# servers/ACServer.py
# ============================================================
# Access Control server (pure Python, FIXED VERSION)
# - Stores ciphertext in "cloud"
# - Stores per-user attributes
# - Verifies against recorded attributes to prevent collusion
# ============================================================

from servers.CloudStorage import CloudStorage


class AccessControlServer:
    def __init__(self, aa):
        """
        aa : AttributeAuthority instance (to share user info)
        """
        self.aa = aa
        self.cloud = CloudStorage()
        self.user_table = {}   # user_id -> (ID_i, QID_i)
        self.user_attrs = {}   # user_id -> set(attributes) actually issued

    # ---------- Storage ----------
    def store_ciphertext(self, file_id: str, CT0: dict):
        self.cloud.upload(file_id, CT0)

    def fetch_ciphertext(self, file_id: str):
        return self.cloud.download(file_id)

    # ---------- Registration from AA ----------
    def register_user_from_aa(self, user_id: str, ID_i, QID_i, S):
        """
        Store:
            - identity data
            - attribute set actually granted to this user
        """
        self.user_table[user_id] = (ID_i, QID_i)
        self.user_attrs[user_id] = set(S)

    # ---------- Token verification (simplified) ----------
    def verify_token(self, user_id: str, PSK_IDi: bytes, ID_i):
        """
        In real paper: PSK_IDi * P == QID_i + h2(...) * Tpub_AA

        Here (demo):
        - Just check that we know this user_id
        - And that ID_i matches what AA registered
        """
        if user_id not in self.user_table:
            return False

        ID_i_ref, _ = self.user_table[user_id]
        return ID_i_ref == ID_i

    # ---------- Partial decrypt (FIXED) ----------
    def partial_decrypt(self, user_id: str, file_id: str, SK: dict):
        """
        Check if user attributes satisfy AS AND
        ensure that SK["S"] matches the attribute set the AA actually
        issued to this user_id.

        This prevents collusion: if someone combines attributes from
        two different SKs, the union set will differ from what we
        recorded for that user.
        """

        CT0 = self.fetch_ciphertext(file_id)
        CT = CT0["CT"]

        # Access policy
        policy_AS = set(CT["AS"])

        # Attribute set in SK
        S_from_SK = SK["S"]

        # Recorded attribute set for this user_id
        if user_id not in self.user_attrs:
            raise PermissionError("Unknown user at AC.")

        S_recorded = self.user_attrs[user_id]

        # === COLLUSION PREVENTION CHECK ===
        if S_from_SK != S_recorded:
            raise PermissionError(
                f"Attribute set mismatch. Expected {S_recorded}, got {S_from_SK}. "
                "Possible collusion or tampering."
            )

        # Policy satisfaction check
        if not policy_AS.issubset(S_from_SK):
            raise PermissionError("Attributes do not satisfy policy.")

        # In real scheme, AC would compute 'C' using pairings.
        # Here: we just return a dummy C flag.
        C = b"OK"

        return C, CT0
