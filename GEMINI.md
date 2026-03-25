# GEMINI.md - Project Context

## 🚀 Project Overview
`dotenv-webauthn-crypt` is a drop-in replacement for the traditional `dotenv` library, designed to enhance security for environment variables on Windows systems. It transparently loads environment variables while keeping secrets **encrypted at rest**, protected by **Windows Hello (TPM-backed)**.

### Key Technologies
- **Python**: Core logic and user-facing API.
- **C++ (pybind11)**: Native extension for direct interaction with the Windows WebAuthn API.
- **Cryptography**: AES-256-GCM for encryption and HKDF-SHA256 for key derivation.
- **Windows Hello / WebAuthn**: Biometric/PIN-gated access control for decryption.

### Architecture
1.  **Python App** calls `load_dotenv()`.
2.  **`dotenv_webauthn_crypt`** (Python) triggers the **pybind11 native module** (`_native`).
3.  **Windows WebAuthn API** prompts the user via **Windows Hello**.
4.  A **TPM-backed private key** signs a challenge.
5.  The resulting signature is used to derive a **Master Key**.
6.  A **Vault Key** is derived per-file using HKDF with the Master Key and the vault path.
7.  **AES-256-GCM** decrypts the secrets into the process environment.

---

## 🏗 Building and Running

### Prerequisites
- **Windows 10/11** with a functional TPM and Windows Hello (PIN/Biometric) set up.
- **Python 3.7+**.
- **Visual Studio 2022 Build Tools** with the "Desktop development with C++" workload.

### Installation
To build the native extension and install the package locally:
```powershell
pip install .
```

### Development Build (Native Harness)
To compile the standalone native test harness for debugging WebAuthn calls:
```powershell
& "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /EHsc ext/harness.cpp /link webauthn.lib user32.lib /OUT:harness.exe
```

---

## 🧪 Testing

### Python Tests
Run the core logic tests (key derivation, etc.):
```powershell
python -m unittest tests/test_core.py
```

### Native Verification
Run the compiled `harness.exe` to verify Windows Hello interaction:
```powershell
.\harness.exe
```

---

## 🔑 Key Management Strategy
- **Root Credential**: Stored at `%LOCALAPPDATA%\dotenv-webauthn\credential.bin`. It contains the `credential_id` created via WebAuthn.
- **Master Key**: Derived via `SHA256(WebAuthnSignature)`.
- **Vault Key**: Derived via `HKDF(MasterKey, salt=SHA256(env_path), info="dotenv-webauthn-v1")`.

---

## 🐍 Python API Usage
```python
from dotenv_webauthn_crypt import load_dotenv

# Behavior:
# 1. Detects encrypted values (starting with 'ENC:') in .env
# 2. Prompts for Windows Hello if secrets are found
# 3. Decrypts and loads into os.environ
load_dotenv()
```

---

## ⚙️ CLI Tool
Invoked via: `python -m dotenv_webauthn_crypt`

### Commands (Implementation Status)
- `init`: (TODO) Create root credential in AppData.
- `encrypt`: (TODO) Encrypt a plaintext `.env` into `.env.vault`.
- `decrypt`: (TODO) Decrypt a vault and output plaintext.
- `rekey`: (TODO) Rotate credentials.

---

## 🧩 Development Conventions
- **Naming**: Always use `webauthn` (not `webauth`) for consistency.
- **Native Code**: The C++ module (`ext/native.cpp`) is the interface to `webauthn.h`.
- **Error Handling**: `HRESULT` from Windows APIs must be correctly interpreted. `0x80090027` (NTE_INVALID_PARAMETER) and `0x800704c7` (ERROR_CANCELLED) are common during development.
- **Security**: Never log or print the Master Key, Vault Key, or Plaintext secrets.
