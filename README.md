# 🔐 Identity-Bound CP-ABE with Traceability for Secure Medical Data Sharing  
### Collusion Resistance • Anonymous Identities • Traceability • Outsourced Decryption  
**Based on the Cryptographic Framework from Sensors (MDPI), 2020**

---

## 🌟 Project Overview

This project implements, analyzes, and enhances a CP-ABE (Ciphertext-Policy Attribute-Based Encryption) scheme for secure medical data sharing in IoMT systems.

While studying the 2020 Sensors CP-ABE construction, we discovered a **collusion vulnerability** in its key-generation mechanism, where multiple unauthorized users can **combine their attribute components** to decrypt sensitive medical records.

### 🔍 Key Problem Found  
In the original scheme:
- Attribute keys depend **only on attributes**, not on user identity.  
- Thus, users can **pool attributes** and satisfy policies they individually cannot.

### 🛠 Our Contribution  
We introduce a **lightweight identity-binding mechanism** that:

✔ Prevents attribute pooling and collusion  
✔ Preserves ciphertext structure  
✔ Supports outsourced decryption  
✔ Maintains user anonymity  
✔ Maintains traceability (QIDᵢ, PSKᵢ)  
✔ Uses minimal extra computation  

Both the **baseline behavior** (from Sensors 2020) and the **identity-bound improved version** are implemented.

---

## 🛡 Full Traceability Support

Our implementation includes the same traceability design proposed in the Sensors paper:

Each user receives:
- **QIDᵢ = dᵢ ⋅ P** → public identity tag  
- **PSKᵢ = dᵢ + h₂(IDᵢ || QIDᵢ) ⋅ α** → private trace key  

The AC server verifies:
PSKᵢ ⋅ P == QIDᵢ + h₂(IDᵢ || QIDᵢ) ⋅ Tpub

yaml
Copy code

Traceability ensures:
- leaked keys can be traced  
- unauthorized key sharing detected  
- user identities remain anonymous  

Our identity-binding fix **does not affect traceability** — it remains fully functional.

---

## 📁 Folder Structure

````text
BTP/
│
├── cpabe/                              # Full CP-ABE implementation
│   │
│   ├── fixed/                          # Identity-bound CP-ABE (secure version)
│   │   ├── decrypt_final.py            # Final decryption + verification (fixed)
│   │   ├── decrypt_partial.py          # AC-server partial decrypt (fixed)
│   │   ├── encrypt.py                  # Encryption algorithm
│   │   ├── keygen.py                   # Identity-bound key generation
│   │   └── scheme.py                   # Core pairing-based CP-ABE scheme logic
│   │
│   ├── flawed/                         # Baseline Sensors-2020 behaviour
│   │   ├── decrypt_final.py            # Final decrypt (baseline)
│   │   ├── decrypt_partial.py          # Partial decrypt (baseline)
│   │   ├── encrypt.py                  # Encryption (baseline)
│   │   ├── keygen.py                   # Attribute-only keygen (collusion-prone)
│   │   └── scheme.py                   # Baseline CP-ABE structure
│   │
│   └── utils/                          # Common helper modules
│       ├── hashing.py                  # Hash → ZR helper
│       ├── kdf.py                      # KDF for deriving symmetric key
│       └── verification.py             # VK signature verification helpers
│
├── data/
│   └── ecg_data.csv                    # Sample medical dataset used for demo
│
├── tests/
│   └── test_common.py                  # Demonstrates collusion + fix + tracing
│
├── main.py                             # Optional runner (encrypt/decrypt example)
└── README.md                           # Project documentation

````
## ⚠️ Problem Identified: Attribute-Pooling Collusion

The baseline scheme generates attribute keys as:
```bash
QID[attr] = g^(w[attr])
```

Since these are identical for all users with the same attribute:

User A (Doctor)

User B (Cardiology)

can combine:

```bash
g^(w[Doctor]) * g^(w[Cardiology])
```

This satisfies a policy:
```bash
Doctor AND Cardiology
```

Even though neither user is authorized individually.

This is the exact vulnerability.

## 🔧 Our Enhancement: Identity-Bound Attribute Keys

We bind all decryption components to a user-specific value:
```bash
h_i = H(ID_i)
```

Enhanced components:
```bash
D*_attr = g^(r_attr + h_i)
D'_i    = g^(α - Σr_attr + h_i)
```

If colluding users A and B combine keys, they get:
```bash
g^(r_A + r_B + h_A + h_B)
```

But a valid decrypt requires:
```bash
g^((r_A+r_B) + (|P|+1) * h_A)
```

The mismatch ensures:

- AC partial decryption breaks

- Final decryption breaks

- Verification fails

- Collusion cannot work

## 📥 Installation & Setup
1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
```
2️⃣ Create a Virtual Environment (Recommended)
```bash
python3 -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows
```
3️⃣ Install Dependencies

Charm Crypto supports Python 3.7–3.8.
```bash
pip install charm-crypto
```

Optional extra packages:
```bash
pip install numpy pandas
```
## ▶️ Running the Project
Run the Demonstration Test
```bash
python tests/test_common.py
```

This will show:

- Correct decryption

- Incorrect decryption

- Traceability verification

- Collusion attack results

Optional: Run Main Script
```bash
python main.py
```
## 🧪 Expected Results
1️⃣ Functional Behaviour Comparison
| Test Case            | Baseline (Paper Behavior)     | Identity-Bound Version    |
|----------------------|-------------------------------|---------------------------|
| Authorized user      | ✔ decrypts                    | ✔ decrypts                |
| Unauthorized user    | ❌ fails                       | ❌ fails                   |
| Two users colluding  | ✔ decrypts *(vulnerability)*  | ❌ fails *(blocked)*       |
| Traceability check   | ✔ works                       | ✔ works                   |


2️⃣ Security Properties Comparison
| Feature / Security Property | Baseline Scheme | Improved Scheme |
|-----------------------------|-----------------|-----------------|
| Collusion resistance        | ❌ No           | ✔ Yes           |
| Identity binding            | ❌ Absent       | ✔ Added         |
| Ciphertext unchanged        | ✔ Yes           | ✔ Yes           |
| Anonymity                   | ✔ Preserved     | ✔ Preserved     |
| Traceability                | ✔ Works         | ✔ Works         |
| Overhead                    | Low             | Low (same)      |

## 📊 Dataset Included

The Sample dataset:
````text
data/ecg_data.csv
````

represents ECG-like medical readings to demonstrate:

- Encryption correctness

- Access control

- Collusion behavior

- Traceability workflow

## 🏁 Conclusion

This implementation:

- Reproduces the attribute-pooling vulnerability from the Sensors 2020 CP-ABE scheme

- Introduces a lightweight identity-bound improvement

- Ensures:
  - Collusion resistance
  - Anonymity
  - Traceability
  - Outsourced decryption efficiency
  - Backwards compatibility

- Validates results using real encrypted medical data

This makes the enhanced scheme suitable for real-world IoMT and healthcare cloud deployments.

## 📚 Reference

Based on the CP-ABE construction from:
````text
A Secure and Efficient CP-ABE Scheme with Verifiable Outsourced Decryption for IoMT,
Sensors (MDPI), 2020.
````
Our implementation identifies and corrects the attribute-pooling weakness in the original design.

