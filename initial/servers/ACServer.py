# servers/ACServer.py
# ============================================================
# Access Control server (pure Python demo version)
# - Stores ciphertext in "cloud"
# - Verifies token (soft check)
# - Performs partial_decrypt(CT, AU*, SK) -> C
# ============================================================

from servers.CloudStorage import CloudStorage


class AccessControlServer:
    def __init__(self, aa): # AC server is created ad it receives a reference to AA 
        """
        aa : AttributeAuthority instance (to share user info)
        """
        self.aa = aa
        self.cloud = CloudStorage()
        self.user_table = {}   # user_id -> (ID_i, QID_i)

    # ---------- Storage ----------
    def store_ciphertext(self, file_id: str, CT0: dict):
        self.cloud.upload(file_id, CT0)

    def fetch_ciphertext(self, file_id: str):
        return self.cloud.download(file_id)

    # ---------- Registration from AA ----------
    def register_user_from_aa(self, user_id: str, ID_i, QID_i):
        self.user_table[user_id] = (ID_i, QID_i)

    # ---------- Token verification (simplified) ----------
    def verify_token(self, user_id: str, PSK_IDi: bytes, ID_i):
        """
        In the real paper: PSK_IDi * P == QID_i + h2(...) * Tpub_AA

        Here (pure Python demo):
        - Just check that we know this user_id
        - And that ID_i matches what AA registered
        """
        if user_id not in self.user_table:
            return False

        ID_i_ref, _ = self.user_table[user_id]
        return ID_i_ref == ID_i

    # ---------- Partial decrypt ----------
    def partial_decrypt(self, file_id: str, SK: dict):
        """
        Check if user attributes satisfy AS. If yes, return dummy C and CT0.
        """

        CT0 = self.fetch_ciphertext(file_id)
        CT = CT0["CT"]

        policy_AS = set(CT["AS"])
        user_attrs = SK["S"]

        if not policy_AS.issubset(user_attrs):
            raise PermissionError("User attributes do not satisfy policy.")

        # In real scheme, AC would compute C using pairings.
        # Here: we just return a dummy C flag.
        C = b"OK"

        return C, CT0
