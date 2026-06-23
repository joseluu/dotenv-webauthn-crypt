# GEMINI.md - Project Context

##  Project Overview
`dotenv-webauthn-crypt` is a drop-in replacement for the traditional `dotenv` library, designed to enhance security for environment variables on Windows systems. It transparently loads environment variables while keeping secrets **encrypted at rest**, protected by **Windows Hello (TPM-backed)**.

### Key Technologies
- **Python**: Core logic and user-facing API.
- **C++ (pybind11)**: Native extension for direct interaction with the Windows WebAuthn API.
- **Cryptography**: AES-256-GCM for encryption and HKDF-SHA256 for key derivation.
- **Windows Hello / WebAuthn**: Biometric/PIN-gated access control for decryption.

### Architecture
1.  **Python App** calls `load_dotenv()`.
2.  **`dotenv_webauthn_crypt`** (Python) triggers the **pybind11 native module** (`_webauthn`).
3.  **Windows WebAuthn API** prompts the user via **Windows Hello**.
4.  A **TPM-backed private key** signs a challenge.
5.  The resulting signature is used to derive a **Master Key**.
6.  A **Vault Key** is derived per-file using HKDF with the Master Key and the vault path.
7.  **AES-256-GCM** decrypts the secrets into the process environment.

---

##  Building and Running

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
cl.exe /EHsc ext/test_webauthn.cpp /link webauthn.lib user32.lib /OUT:test_webauthn.exe
```

---

##  Testing

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

##  Key Management Strategy
- **Root Credential**: Stored at `%LOCALAPPDATA%\dotenv-webauthn\credential.bin`. It contains the `credential_id` created via WebAuthn.
- **Master Key**: Derived via `SHA256(WebAuthnSignature)`.
- **Vault Key**: Derived via `HKDF(MasterKey, salt=SHA256(env_path), info="dotenv-webauthn-v1")`.

---

##  Python API Usage
```python
from dotenv_webauthn_crypt import load_dotenv

# Behavior:
# 1. Detects encrypted values (starting with 'ENC:') in .env
# 2. Prompts for Windows Hello if secrets are found
# 3. Decrypts and loads into os.environ
load_dotenv()
```

---

##  CLI Tool
Invoked via: `python -m dotenv_webauthn_crypt`

### Commands (Implementation Status)
- `init`: Create root credential in AppData.
- `encrypt`: Encrypt a plaintext `.env` file into itself `.env`.
- `decrypt`: Decrypt a vault and output plaintext.
- `rekey`: (TODO) Rotate credentials.

---

##  Cross-Platform Backend (Linux / macOS / WSL)
The WebAuthn backend is selected at import time by `dotenv_webauthn_crypt/_backend.py`:
- **Windows** → the native `_webauthn` C++ extension (system `WebAuthN*` API). RP ID `credentials.dotenv-webauthn.com`.
- **Other OSes** → `_browser.py`, a pure-Python backend that serves a one-shot page on `http://localhost:8580` and delegates `navigator.credentials.create()/.get()` to the user's browser. RP ID `localhost`. No compiler needed (`setup.py` skips the extension off Windows).

Both backends expose the same callables. `_backend` normalizes one field: `get_assertion` always returns `client_data_hash` (the 32-byte hash that was actually signed), because it differs per platform — `SHA256(challenge)` for the native API vs `SHA256(clientDataJSON)` for the browser. `core._recover_public_key` consumes that hash, so the crypto core is platform-agnostic.

Determinism requirement: the master key is recovered from a fresh assertion signature each load, so the authenticator must produce a **stable signature** for the fixed challenge (deterministic ECDSA + stable signCount). True for Windows Hello / Touch ID / most FIDO2 keys.

Under WSL the Linux HTTP server is reachable from the Windows browser via localhost forwarding, so Windows Hello satisfies the prompt from inside Linux. `_browser._open_browser` falls back to `cmd.exe`/`powershell.exe`/`wslview` when no Linux browser is installed.

##  Development Conventions
- **Naming**: Always use `webauthn` (not `webauth`) for consistency.
- **Native Code**: The C++ module (`ext/_webauthn.cpp`) is the interface to `webauthn.h` (Windows only).
- **Error Handling**: `HRESULT` from Windows APIs must be correctly interpreted. `0x80090027` (NTE_INVALID_PARAMETER) and `0x800704c7` (ERROR_CANCELLED) are common during development.
- **Security**: Never log or print Plaintext secrets.
- **Version numbering**: once automatic and manual tests are passed bump minor version (x) to 0.1.x in the toml file in the ext/_webauthn.cpp and in the setup.py , commit and push, tag v0.1.x push tag
