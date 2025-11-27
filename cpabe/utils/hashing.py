

from charm.toolbox.pairinggroup import ZR

def hash_to_ZR(group, data):
    """
    Safely hash arbitrary data (bytes or group element) into ZR.
    """
    if isinstance(data, bytes):
        raw = data
    else:
        raw = group.serialize(data)
    return group.hash(raw, ZR)
