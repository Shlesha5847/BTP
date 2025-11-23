from authorities.AA import AttributeAuthority
from authorities.TA import TraceAuthority
from servers.ACServer import ACServer
from client.User import User
from crypto.Encrypt import encrypt

# Setup authorities
U = ["Doctor", "Nurse", "Cardiology"]
aa = AttributeAuthority(U)
ta = TraceAuthority()
ac = ACServer()

# Register user at TA
RID = "RealID123"
ID = ta.register(RID, "Tanisha", "2025")
user_attrs = {"Doctor", "Cardiology"}
user_SK = aa.keygen(ID, user_attrs)
user = User(user_SK)

# Encrypt medical record
message = b"ECG Report: Stable"
AS = {"Doctor", "Cardiology"}
CT0 = encrypt(aa.PK, message, AS)
ac.store("record001", CT0)

# Outsourced partial decrypt
C, CTX = ac.partial_decrypt("record001", user_SK)

# Final decrypt
M = user.final_decrypt(C, CTX)
print("Decrypted message:", M.decode())
