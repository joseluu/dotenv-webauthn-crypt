#  dotenv-webauthn-crypt

**Transparent, WebAuthn-backed encryption for your `.env` files.**

`dotenv-webauthn-crypt` is a drop-in replacement for `python-dotenv` that keeps your secrets **encrypted at rest** and gates access behind **WebAuthn (Biometrics/PIN/Phone)**. Your Master Key never exists in plaintext on disk.

##  Features

-   **Seamless Integration**: Use `load_dotenv()` just like you always have.
-   **Multiple Authentication Devices**: Windows Hello (fingerprint/PIN), smartphone (QR code), or USB security key.
-   **Hardware Security**: Private keys stay in the TPM or on your authenticator device.
-   **Strong Cryptography**: AES-256-GCM encryption, HKDF-SHA256 key derivation.
-   **Vault Isolation**: Each `.env` file has its own unique derived vault key.
-   **Platform Diagnostics**: Pre-flight checks for TPM, Bluetooth, and network availability.

##  Installation

### Prerequisites
-   **Windows 10/11** with Windows Hello enabled (for local authentication).
-   **Bluetooth + Network** (for phone/QR authentication).
-   **Visual Studio 2022 Build Tools** (only if building from source).

```powershell
pip install dotenv-webauthn-crypt
```

##  Usage

### 1. Check available devices

Running `init` without `--device` shows a diagnostic report and available options.
`--user` defaults to your Windows username if not specified:

```powershell
dotenv-webauthn-crypt-cli init
```

Output:
```
--- Platform Authentication Status ---
  WebAuthn API version: 9
  Platform authenticator: available
  Bluetooth: available
  Network: available

  Choose an authentication device with --device:

    --device local   Windows Hello (fingerprint/PIN)
                     Credential stored in the local TPM.
                     Fast, no extra hardware needed.

    --device phone   Smartphone via QR code (hybrid)
                     Credential stored on your phone.
                     Requires Bluetooth + network.

    --device usb     USB security key (FIDO2)
                     Credential stored on the key.
                     Requires a compatible USB key.
```

### 2. Initialize with your chosen device

`--user` defaults to your Windows username (`%USERNAME%`) if omitted:

```powershell
# Windows Hello (fingerprint/PIN) — uses Windows username
dotenv-webauthn-crypt-cli init --device local

# Smartphone via QR code — custom user name
dotenv-webauthn-crypt-cli init --device phone --user MyUser

# USB security key
dotenv-webauthn-crypt-cli init --device usb
```

### 3. Encrypt an existing .env file

If no file is specified, defaults to `.env` in the current directory:
```powershell
dotenv-webauthn-crypt-cli encrypt
```

The encrypted file includes a recovery header with credential metadata:
```
# --- dotenv-webauthn-crypt recovery info ---
# CREDENTIAL_ID="hnemG/M2FN..."
# RP_ID="credentials.dotenv-webauthn.com"
# USER_NAME="MyUser"
# DEVICE="local"
# TRANSPORT="internal"
# AAGUID="adce0002-35bc-c60a-648b-0b25f1f05503"
# CREATED_AT="2026-04-02T10:30:00Z"
# ENCRYPTED_AT="2026-04-02T10:31:00Z"
# VAULT_PATH="C:\Projects\myapp\.env"
# --- end recovery info ---
MY_SECRET=ENC:AQ...
```

### 4. Inspect your credential
```powershell
dotenv-webauthn-crypt-cli info
```

Output:
```
--- Credential Information ---
  Credential ID : hnemG/M2FNfuigrJ3BUP5kj9DYudDEL1...
  Domain (RP_ID): credentials.dotenv-webauthn.com
  User name     : MyUser
  Device        : local (Windows Hello (fingerprint/PIN))
  Transport     : internal
  AAGUID        : adce0002-35bc-c60a-648b-0b25f1f05503
  Authenticator : Windows Hello
  Created at    : 2026-04-02T10:30:00Z
```

The `info` command also queries the [AAGUID database](https://github.com/passkeydeveloper/passkey-authenticator-aaguids) to display the authenticator name (e.g., "Samsung Galaxy", "YubiKey 5").

### 5. Load in your Python code
```python
from dotenv_webauthn_crypt import load_dotenv

# Triggers an authentication prompt if encrypted values are detected
load_dotenv()  # comment lines in the .env file are ignored

import os
print(os.environ.get("MY_SECRET_KEY"))
```

## Authentication Devices

| Device | `--device` | Where key lives | Requirements |
|--------|-----------|----------------|--------------|
| Windows Hello | `local` | Local TPM | Windows Hello PIN or biometrics |
| Smartphone | `phone` | Phone | Bluetooth + network connectivity |
| USB key | `usb` | Security key | FIDO2-compatible USB key |

The `init` command runs pre-flight diagnostics and reports which devices are available. If a device is unavailable, it explains why (e.g., Bluetooth off, no network, no TPM).

##  Architecture

1.  **Registration**: `init` creates a non-resident public/private key pair on the chosen authenticator. The `CredentialID` and metadata (AAGUID, transport, device, user, timestamp) are saved locally.
2.  **Encryption**: A `VaultKey` is derived using HKDF from an authenticator-backed signature and the file's canonical path. A recovery header with credential metadata is prepended to the encrypted file.
3.  **Loading**: `load_dotenv` skips comment lines (`#`), detects `ENC:` prefixes, triggers authentication to get a fresh signature, re-derives the `VaultKey`, and decrypts the values into `os.environ`.
4.  **Info**: `info` reads the credential metadata and queries the [AAGUID database](https://github.com/passkeydeveloper/passkey-authenticator-aaguids) to identify the authenticator model.

##  TODO / Roadmap

- [x] Windows Hello (TPM) authentication
- [x] Smartphone (hybrid/QR) authentication
- [x] USB security key authentication
- [x] Platform diagnostics (TPM, Bluetooth, network)
- [x] Credential metadata and recovery headers
- [x] AAGUID-based authenticator identification
- [ ] **Linux Support**: Backend using **TPM2-TSS** or **libfido2**.
- [ ] **macOS Support**: Backend using **Secure Enclave / Touch ID**.
- [ ] **Credential Rotation**: `rekey` command to migrate between hardware credentials.

## Browser-based WebAuthn Test

`tests/test_browser_webauthn.py` is a standalone prototype that uses a local browser as the WebAuthn client instead of the native C++ module. It starts an HTTP server on `localhost:8580`, opens the default browser, and delegates `navigator.credentials.create()` / `.get()` to the browser's built-in WebAuthn support.

**Prerequisites**: Windows Hello must be provisioned (NGC active). See `TODO_BUGS.md` for NGC troubleshooting.

```bash
# Create a platform credential (triggers Windows Hello in the browser)
python tests/test_browser_webauthn.py create

# Sign with the saved credential
python tests/test_browser_webauthn.py sign
```

##  License

Distributed under the MIT License. See `LICENSE` for more information.
