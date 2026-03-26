#  dotenv-webauthn-crypt

**Transparent, Windows Hello-backed encryption for your `.env` files.**

`dotenv-webauthn-crypt` is a drop-in replacement for `python-dotenv` that keeps your secrets **encrypted at rest** and gates access behind **WebAuthn (Biometrics/PIN)**. It, ensuring that your Master Key never exists in plaintext on disk.

##  Features

-   **Seamless Integration**: Use `load_dotenv()` just like you always have.
-   **Hardware Security**: Private keys stay in the TPM.
-   **Biometric Decryption**: Prompts for Fingerprint/PIN when loading secrets.
-   **Strong Cryptography**: Uses AES-256-GCM for encryption and HKDF-SHA256 for key derivation.
-   **Vault Isolation**: Each `.env` file has its own unique derived vault key.

##  Installation

### Prerequisites
-   **Windows 10/11** with Windows Hello enabled.
-   **Visual Studio 2022 Build Tools** (only if building from source).

```powershell
pip install dotenv-webauthn-crypt
```

##  Usage

### 1. Initialize your machine
Create your machine-specific root credential in the TPM:
```powershell
dotenv-webauthn-crypt-cli init --user MyWindowsUser
```

### 2. Encrypt an existing .env file
This will replace plaintext values with encrypted `ENC:...` blobs:
```powershell
dotenv-webauthn-crypt-cli encrypt .env
```

### 3. Load in your Python code
```python
from dotenv_webauthn_crypt import load_dotenv

# This will trigger a Windows Hello prompt if encrypted values are detected
load_dotenv()

import os
print(os.environ.get("MY_SECRET_KEY"))
```

##  Architecture

1.  **Registration**: `init` creates a non-resident public/private key pair in the TPM. The `CredentialID` is saved locally.
2.  **Encryption**: A `VaultKey` is derived using HKDF from a TPM-backed signature and the file's canonical path.
3.  **Loading**: `load_dotenv` detects `ENC:` prefixes, triggers Windows Hello to get a fresh signature, re-derives the `VaultKey`, and decrypts the values into `os.environ`.

##  TODO / Roadmap

- [ ] Usage of Windows Hello as it uses the TPM (Trusted Platform Module) to sign challenges
- [ ] **Linux Support**: Implement a Linux backend using the **TPM2-TSS** or **libfido2** for similar biometric/hardware protection.
- [ ] **macOS Support**: Implement a macOS backend using **Secure Enclave / Touch ID**.
- [ ] **Credential Rotation**: Add `rekey` command to migrate between hardware credentials.

##  License

Distributed under the MIT License. See `LICENSE` for more information.


