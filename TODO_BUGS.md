# TODO / Bugs

## BUG: Platform authenticator (Windows Hello) fails for non-browser callers

**Status:** Open — root cause unknown
**Date:** 2026-03-28
**Machine:** DELL-JOSE-2T, Windows 11 Home 10.0.26200

### Symptom

Calling `WebAuthNAuthenticatorMakeCredential` with `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM` always fails. The Windows Security dialog appears but shows **"Something went wrong — There was a problem saving your passkey"**. The only option is "Try again" (which loops) or cancel. Cancelling returns `HRESULT 0x800704C7` (`ERROR_CANCELLED` / `NotAllowedError`).

This affects:
- The pybind11 native module (`_webauthn.cpp`) called from Python
- A standalone C++ test executable (`test_webauthn.cpp`)

`WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM` works fine (phone/QR flow).

### What works

- Creating a passkey for **gitlab.com via Chrome** using Windows Hello (platform authenticator) succeeds — the credential is stored locally on the TPM.
- `WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable()` returns TRUE.
- `CROSS_PLATFORM` attachment works (smartphone via QR code).
- `ANY` attachment (value 0) shows the platform save dialog, which appears to fail silently, then falls back to the cross-platform QR flow. The API reports `dwUsedTransport=32` (INTERNAL) but the credential was actually completed via the phone.

### Diagnostics collected

```
WebAuthN API version:          9
Platform authenticator:        AVAILABLE
SDK MAKE_CREDENTIAL_OPTIONS:   CURRENT_VERSION = 7
Window handle (HWND):          valid (GetConsoleWindow)

dsregcmd /status:
  NgcSet:           NO
  PolicyEnabled:    NO
  PreReqResult:     WillNotProvision
  DeviceEligible:   YES
  IsDeviceJoined:   NO (not Azure AD joined)

Crypto providers present:
  Microsoft Platform Crypto Provider
  Microsoft Passport Key Storage Provider
  Microsoft Smart Card Key Storage Provider
```

Windows Hello PIN is configured and functional.

### What was tested (all failed with PLATFORM)

| Test | Options version | bRequireResidentKey | RP ID | ClientData | Result |
|------|----------------|--------------------|----|------------|--------|
| CURRENT_VERSION (7) | 7 | TRUE | dotenv-vault.local | JSON with origin | CANCELLED |
| VERSION_4 | 4 | TRUE | dotenv-vault.local | JSON with origin | CANCELLED |
| VERSION_4 | 4 | FALSE | dotenv-vault.local | JSON no origin | CANCELLED |
| VERSION_1 | 1 | FALSE | dotenv-vault.local | JSON no origin | CANCELLED |
| VERSION_4 | 4 | FALSE | dotenv-webauthn-crypt | raw bytes | CANCELLED |
| VERSION_4 | 4 | FALSE | dotenv-webauthn-crypt | JSON no origin | CANCELLED |
| VERSION_4 | 4 | FALSE | dotenv-vault.local | raw bytes | CANCELLED |
| VERSION_4 | 4 | FALSE | credentials.dotenv-webauthn.com | raw bytes | CANCELLED |
| VERSION_4 | 4 | FALSE | localhost | raw bytes | not reached |
| VERSION_4 | 4 | FALSE | gitlab.com | raw bytes | not reached |

None of the parameter combinations (version, residentKey, RP ID, clientData format) made a difference.

### Hypotheses

#### 1. Browser-privileged code path (MOST LIKELY)
Chrome uses a different code path to talk to Windows Hello. Chromium dynamically loads `webauthn.dll` and may use internal flags, enterprise attestation, or a browser-specific AppId context that non-browser processes don't have. The Windows WebAuthn API may restrict platform credential creation to registered/trusted callers (browsers).

**Evidence:** gitlab.com passkey creation via Chrome works. Direct API calls from console apps and Python do not.

#### 2. NGC (Next Generation Credential) not provisioned
`dsregcmd /status` shows `NgcSet: NO` and `PreReqResult: WillNotProvision`. This suggests Windows Hello FIDO2 platform credentials are not fully provisioned at the OS level. The browser may bypass this via a different credential storage mechanism.

**Evidence:** NGC-related fields all show disabled/not-provisioned state despite Windows Hello PIN being functional.

#### 3. HWND context insufficient
Console apps provide `GetConsoleWindow()` or `GetForegroundWindow()` as HWND. The Windows Hello dialog may require a proper top-level application window with a message pump. Browsers have this; bare console apps and Python processes may not.

**Counter-evidence:** The dialog does appear and attempts to save — it's not an HWND rejection. The failure is inside the save operation.

#### 4. Windows 11 Home limitation
Possible that certain FIDO2 platform authenticator features require Windows 11 Pro or Enterprise, or Azure AD join. The device is not domain-joined or Azure AD-joined.

**Counter-evidence:** Chrome can create platform credentials on the same machine.

### Chromium comparison (from source inspection)

Key differences between Chromium's implementation and our code:
- Chromium uses `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_8` (not CURRENT_VERSION)
- Chromium constructs proper JSON clientData with type, challenge, and origin fields
- Chromium dynamically loads `webauthn.dll` via `LoadLibraryExA` with `LOAD_LIBRARY_SEARCH_SYSTEM32`
- Chromium checks `WebAuthNGetApiVersionNumber()` and adapts struct versions accordingly
- Chromium uses 5-minute timeout (300,000ms) vs our 120s
- Chromium populates all extended fields for the version it declares (cancellation ID, exclude list, enterprise attestation, large blob, PRF, etc.)
- Chromium sets both legacy `CredentialList` and extended `pExcludeCredentialList` for compatibility

### Next steps to investigate

1. **Try from a GUI application** (not console) — create a minimal Win32 window with a message loop, call WebAuthn from there. Tests whether HWND context matters.
2. **Try `WebAuthNGetApiVersionNumber()` version-matched options** — fill in ALL fields for the declared version (cancellation ID, exclude list, etc.) instead of zero-initializing.
3. **Check Windows Event Viewer** — look for NGC/WebAuthn/TPM errors in `Applications and Services Logs > Microsoft > Windows > WebAuthn` or `HelloForBusiness`.
4. **Try enabling NGC** — run `ms-settings:signinoptions` and re-enroll Windows Hello PIN/fingerprint.
5. **Compare with Chromium's exact struct layout** — populate every field Chromium does for VERSION_8 including cancellation ID and credential hints.

### Current workaround

Use `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM` which routes to smartphone/QR authentication. This works reliably and is the current production setting.
