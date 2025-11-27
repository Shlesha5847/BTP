# -----------------------------------------------------
# KeyGen (flawed: per-attribute only, no user binding)
# -----------------------------------------------------
from charm.toolbox.pairinggroup import ZR
def keygen(self, pk, user_attrs):
    """
    For each attribute a in user_attrs:

        if w[a] not defined yet: choose random w[a] in Z_p
        QID[a] = g^{w[a]}

    NO per-user randomness, NO identity binding.
    Anybody with QID[a] has that attribute's "power".
    """
    if self.mk is None:
        raise Exception("Run setup() first so mk is available in self.mk")

    g = pk["g"]
    w_map = self.mk["w"]

    QID = {}
    for attr in user_attrs:
        if attr not in w_map:
            w_map[attr] = self.group.random(ZR)
        QID[attr] = g ** w_map[attr]

    sk = {
        "QID": QID,  # per-attribute components
        "attrs": set(user_attrs),  # attribute set this user owns
    }
    return sk
