# Project Specification
## `dotenv-webauthn-crypt`

# 1️⃣ 🎯 Goal
Provide a **drop-in replacement for dotenv** that:
- Transparently loads environment variables 
- Stores secrets **encrypted at rest** 
- Uses **Windows Hello (TPM-backed)** for access control 
- Requires **user presence (biometric/PIN)** to decrypt 

# 2️⃣ 🧠 Core Design Principles
### ✔ Security
- No plaintext secrets stored on disk 
- Private keys never leave TPM 
- All decryption gated by Windows Hello 
### ✔ Simplicity
- Compatible with existing `.env` workflows 
- Minimal user friction 
### ✔ Determinism
- Same vault → same derived key (per credential) 
### ✔ Isolation
- One credential per machine 
- Per-vault derived keys 

# 3️⃣ 🏗 Architecture Overview
```
Python app
```
```
`   ↓`
`dotenv-webauthn-crypt (Python)`
`   ↓`
`pybind11 module (C++)`
`   ↓`
`WebAuthn (Windows Hello)`
`   ↓`
`TPM-backed private key`
```

# 4️⃣ 🔑 Key Management Strategy
## 4.1 Root Credential
- One credential per user/machine 
- Created via WebAuthn 
- Stored locally 
### Storage location:
```
%LOCALAPPDATA%\\dotenv-webauthn\\credential.bin
```
Contents:
```
- credential\_id (binary, base64 when serialized)
- metadata (optional: version, RP ID)
```

## 4.2 Master Key Derivation
On each access:
```
signature = WebAuthnSign(challenge, credential\_id)
master\_key = SHA256(signature)
```

## 4.3 Per-Vault Key Derivation
```
vault\_id = SHA256(canonical\_path\_to\_env\_file)
vault\_key = HKDF(
    input\_key = master\_key,
    salt = vault\_id,
    info = "dotenv-webauthn-v1",
    output\_len = 32
)
```

✔ Ensures:
- Vault isolation 
- No key reuse across files 

# 5️⃣ 🔐 Encryption Scheme
## Algorithm
- AES-256-GCM (authenticated encryption) 

## Encrypted value format
```
base64(
    version (1 byte)
    nonce (12 bytes)
    ciphertext (N bytes)
    tag (16 bytes)
)
```

# 7️⃣ ⚙️ CLI Tool

Invoked via:
```
python -m dotenv\_webauthn\_crypt
```

## 7.1 Commands
### 🔐 `encrypt`
```
python -m dotenv\_webauthn\_crypt encrypt .env
```
- Reads plaintext `.env` 
- Creates credential if needed 
- Encrypts all values 
- Writes `.env.vault` (or overwrites) 

### 🔓 `decrypt` (optional/debug)
```
python -m dotenv\_webauthn\_crypt decrypt .env
```
- Requires Windows Hello 
- Outputs plaintext (stdout or file) 

### 🔄 `rekey`
```
python -m dotenv\_webauthn\_crypt rekey
```
- Creates new credential 
- Re-encrypts all known vaults 

### 🔑 `init`
```
python -m dotenv\_webauthn\_crypt init
```
- Creates credential only 
- Stores in AppData 

# 8️⃣ 🐍 Python API
Drop-in replacement for `dotenv`:
```
from dotenv\_webauthn\_crypt import load\_dotenv
load\_dotenv()
```
### Behavior:
- Detects encrypted values 
- Prompts Windows Hello 
- Decrypts into environment 

# 9️⃣ 🔍 Vault Detection
A file is considered encrypted if:
```
CREDENTIAL\_ID exists
AND values are base64 blobs
```

# 🔟 🔐 Security Properties
## ✔ Protected Against
- Disk theft 
- Source code leaks 
- Git commits of secrets 
- Offline brute force (TPM-bound) 

## ⚠️ Not Protected Against
- User approving malicious Hello prompt 
- Running compromised application 
- Memory inspection after decryption 

# 11️⃣ ⚠️ Failure Modes
## 11.1 Credential Loss
If:
- Windows Hello reset 
- TPM reset 
- OS reinstall
👉 Result:
```
All vaults become undecryptable
```
### Mitigation (recommended):
- Warning to user 
- Optional export/recovery feature 

# 12️⃣ 🧩 C++ Module Responsibilities
- Call WebAuthn APIs 
- Manage credential creation 
- Perform signing 
- Return signature to Python 

### API:
```
std::vector\<uint8\_t\> get\_signature(std::vector\<uint8\_t\> challenge);
```

# 13️⃣ 🧪 Challenge Strategy
Use fixed challenge:
```
"dotenv-webauthn-fixed-challenge"
```
OR slightly better:
```
"dotenv-webauthn:" + vault\_id
```
✔ Ensures consistency

# 14️⃣ 🧠 UX Considerations
- First run → Windows Hello prompt 
- Subsequent decrypt → prompt per session 
- Fast enough for dev workflows 

# 15️⃣ 🔄 Future Extensions
- Multi-device sync (export/import vault) 
- Credential rotation UI 
- Secure backup (secondary key) 
- Linux/macOS fallback (different backend) 

# 16️⃣ 🏁 Final Design Summary
```
1 credential per machine (stored in AppData)
↓
WebAuthn → signature
↓
SHA256 → master key
↓
HKDF(vault\_id) → vault key
↓
AES-GCM → encrypt secrets
↓
stored in .env-compatible format
```
