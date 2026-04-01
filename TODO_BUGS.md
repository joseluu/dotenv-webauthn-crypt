# TODO / Bugs

## BUG: Platform authenticator (Windows Hello) fails for non-browser callers

**Status:** RESOLVED — NGC re-provisioning fixed it
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

### HWND hypothesis test (v3 — 2026-03-28)

Tested whether using a proper Win32 application window (like go-ctap/winhello does)
instead of the console HWND fixes the issue. Created a hidden `WS_POPUP | WS_VISIBLE`
window with `WS_EX_APPWINDOW` and a dedicated message pump thread.

```
Console HWND:     0x0      (NULL — no console window in this session)
Foreground HWND:  0x4d12c2 (some other window)
Hidden app HWND:  0x23e2308 (newly created, valid)
```

| Test | HWND | residentKey | Result |
|------|------|-------------|--------|
| Hidden app window | 0x23e2308 | FALSE | CANCELLED (dialog appeared, failed internally) |
| Console (NULL) | 0x0 | FALSE | **NTE_INVALID_PARAMETER** (different error — NULL rejected) |
| NULL explicit | 0x0 | FALSE | **NTE_INVALID_PARAMETER** |
| Hidden app window | 0x23e2308 | TRUE | CANCELLED (dialog appeared, failed internally) |

**Conclusion:** HWND hypothesis **disproven**. A proper app window with message pump
does NOT fix the platform save failure. However, NULL HWND gives a different error
(`NTE_INVALID_PARAMETER` instead of `ERROR_CANCELLED`), confirming a valid HWND is
needed for the dialog to appear at all. The failure happens *inside* the Windows
Hello credential save operation, after the dialog is displayed.

### Hypotheses (updated)

#### ~~1. HWND context insufficient~~ — DISPROVEN
Tested with a dedicated hidden Win32 application window (`WS_EX_APPWINDOW`,
`WS_POPUP | WS_VISIBLE`, message pump on separate thread). The dialog appeared
but still failed internally. The HWND quality affects whether the dialog shows
(NULL → `NTE_INVALID_PARAMETER`) but does not affect the save outcome.

#### 2. Browser-privileged code path (MOST LIKELY)
Chrome uses a different code path to talk to Windows Hello. Chromium dynamically
loads `webauthn.dll` and may use internal flags, enterprise attestation, or a
browser-specific AppId context that non-browser processes don't have. The Windows
WebAuthn API may restrict platform credential creation to registered/trusted callers.

**Evidence:** gitlab.com passkey creation via Chrome works. Direct API calls from
console apps (with any HWND type) and Python do not. All parameter combinations
tested fail identically.

#### 3. NGC (Next Generation Credential) not provisioned (LIKELY)
`dsregcmd /status` shows `NgcSet: NO` and `PreReqResult: WillNotProvision`.
Windows Hello FIDO2 platform credentials may not be fully provisioned at the
OS level. Chrome may bypass NGC and use its own credential storage path via the
Windows WebAuthn broker.

**Evidence:** NGC-related fields all show disabled/not-provisioned despite PIN
being functional. The API reports platform authenticator as AVAILABLE but the
actual save operation fails — suggesting the high-level check passes but the
low-level NGC storage does not.

#### 4. Missing cancellation ID or extended fields
Firefox and Chromium both set a cancellation ID via `WebAuthNGetCancellationId()`.
Chromium populates all VERSION_8 fields. Our zero-initialized struct may have
NULL in fields the API expects to be valid for the declared version.

#### 5. Windows 11 Home limitation (UNLIKELY)
Possible that platform authenticator features require Pro/Enterprise or Azure AD join.

**Counter-evidence:** Chrome can create platform credentials on the same machine.

### Firefox comparison (from source inspection — 2026-03-28)

Key differences between Firefox (`WinWebAuthnService.cpp`) and our code:
- Firefox uses `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_8`
- Firefox dynamically loads `webauthn.dll` and resolves all 11 function pointers via `GetProcAddress`
- Firefox **always** sets a cancellation ID via `WebAuthNGetCancellationId()`
- Firefox uses `GetForegroundWindow()` (same as us, but Firefox is a GUI app)
- Firefox passes proper JSON clientData
- Firefox sets credProtect and hmac-secret extensions when requested
- Firefox checks API version before choosing features

### Chromium comparison (from source inspection)

Key differences between Chromium's implementation and our code:
- Chromium uses `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_8` (not CURRENT_VERSION)
- Chromium constructs proper JSON clientData with type, challenge, and origin fields
- Chromium dynamically loads `webauthn.dll` via `LoadLibraryExA` with `LOAD_LIBRARY_SEARCH_SYSTEM32`
- Chromium checks `WebAuthNGetApiVersionNumber()` and adapts struct versions accordingly
- Chromium uses 5-minute timeout (300,000ms) vs our 120s
- Chromium populates all extended fields for the version it declares (cancellation ID, exclude list, enterprise attestation, large blob, PRF, etc.)
- Chromium sets both legacy `CredentialList` and extended `pExcludeCredentialList` for compatibility

### Browser-style options test (v4 — 2026-03-28)

Fully replicated Firefox/Chromium-style MakeCredential call: cancellation ID via
`WebAuthNGetCancellationId()`, proper JSON clientData with origin, VERSION_7 with
all fields explicitly populated, empty exclude credential list, 5-minute timeout.
Used hidden app window HWND.

| Test | Version | CancelId | ClientData | ResidentKey | Result |
|------|---------|----------|------------|-------------|--------|
| V7 + cancelId + JSON | 7 | SET | JSON | FALSE | CANCELLED |
| V7 + cancelId + JSON | 7 | SET | JSON | TRUE | CANCELLED |
| V7 + cancelId + raw | 7 | SET | raw bytes | FALSE | CANCELLED |
| V7 + NO cancelId + JSON | 7 | NOT SET | JSON | FALSE | CANCELLED |
| V4 + cancelId + JSON | 4 | SET | JSON | FALSE | CANCELLED |

**Conclusion:** Browser-style options do **NOT** fix the issue. Every parameter
combination produces the same "Something went wrong — problem saving your passkey"
dialog followed by `ERROR_CANCELLED`.

### Definitively ruled out

The following factors have been exhaustively tested and do NOT affect the outcome:
- **Options struct version** (1, 4, 7, CURRENT_VERSION)
- **bRequireResidentKey** (TRUE, FALSE)
- **RP ID** (dotenv-vault.local, dotenv-webauthn-crypt, credentials.dotenv-webauthn.com, localhost, gitlab.com)
- **ClientData format** (raw bytes, JSON without origin, JSON with origin + crossOrigin)
- **HWND type** (console, foreground, hidden app window with message pump, NULL)
- **Cancellation ID** (set via WebAuthNGetCancellationId, not set)
- **Exclude credential list** (empty list, not set)
- **Extended fields** (all populated for declared version, all zero-initialized)
- **Timeout** (60s, 120s, 300s)

### ROOT CAUSE IDENTIFIED (2026-03-28) — Event Viewer analysis

Full event chain from `Microsoft-Windows-WebAuthN/Operational` log for a single
PLATFORM MakeCredential attempt (read bottom-to-top for chronological order):

```
[5:40:48 PM] INFO  1000  WebAuthN Ctap MakeCredential started.
                          TransactionId: {ca77bc8f-...}

[5:40:48 PM] ERROR 1060  WebAuthN error at: DsrGetJoinInfoNoAccessTokenUrl
                          Error: 0x8000FFFF. Catastrophic failure
                          → Machine is not domain/Azure AD joined. This call fails immediately.

[5:40:48 PM] INFO  1101  Cbor encode MakeCredential request.
                          RpId: credentials.dotenv-webauthn.com
                          ClientDataHashAlgId: SHA-256

[5:40:48 PM] INFO  2106  Ctap Name: APPID://FQBN Value: (empty)
                          → No FQBN (Fully Qualified Binary Name) for the calling process.
[5:40:48 PM] INFO  2106  Ctap Name: TokenPublisher Value: (empty)
                          → No publisher from process token.
[5:40:48 PM] INFO  2106  Ctap Name: ImageName Value: ...\test_webauthn.exe

[5:40:48 PM] WARN  2105  Ctap Function: _CtapSrvGetPublisherFromImageName
                          Location: NoImpersonateGetInfo
                          Error: 0x80070005. Access is denied.
                          → Cannot read Authenticode signature from the unsigned exe.

[5:40:48 PM] WARN  2105  Ctap Function: _CtapSrvGetPublisherFromImageName
                          Location: SigState
                          Error: 0x80090011. Object was not found.
                          → No signature found on the executable.

[5:40:48 PM] INFO  2106  Ctap Name: ImagePublisher Value: (empty)
                          → Publisher remains empty — exe is unsigned.
[5:40:48 PM] INFO  2106  Ctap Name: Application Value: ...\test_webauthn.exe

[5:40:48 PM] ERROR 2103  Ctap GetPluginAuthenticatorList completed.
                          Error: 0x80090011. Object was not found.
                          → No plugin authenticators available.

[5:40:50 PM] INFO  1020  WebAuthN Ngc MakeCredential started.
                          → Windows Hello dialog appears, user authenticates with fingerprint.

[5:40:53 PM] ERROR 1022  WebAuthN Ngc MakeCredential completed.
                          Error: 0x80090029. The requested operation is not supported.
                          → NGC credential creation FAILS. This is the actual failure point.
                          → Dialog shows "Something went wrong — problem saving your passkey".

[5:40:55 PM] WARN  2105  ProcessWebAuthNCommandCallback Location: Stop
                          Error: 0x800704C7. The operation was canceled by the user.
                          → User cancels the failed dialog.

[5:40:55 PM] ERROR 1002  WebAuthN Ctap MakeCredential completed.
                          Error: 0x800704C7. The operation was canceled by the user.
                          → Final result returned to our code.
```

#### HelloForBusiness log (same timeframe):
```
Creating a software Windows Hello key with result 0x80090029.
→ NTE_NOT_SUPPORTED — NGC key creation explicitly fails.
```

#### Biometrics log (same timeframe):
```
(Informational) Successfully identified user via Goodix MOC Fingerprint.
→ Biometric auth works. The failure is in the credential STORE, not in user auth.
```

### Three issues identified

#### Issue A: `DsrGetJoinInfoNoAccessTokenUrl` → `0x8000FFFF (Catastrophic failure)`
The very first thing WebAuthn does is check domain/Azure AD join status via
`DsrGetJoinInfoNoAccessTokenUrl`. This fails with `E_UNEXPECTED` because the
machine is not domain-joined. This may prevent the NGC path from initializing.

#### Issue B: Unsigned executable → publisher check fails
`_CtapSrvGetPublisherFromImageName` tries to read the Authenticode signature.
Results in two warnings:
- `NoImpersonateGetInfo`: `0x80070005 (Access is denied)` — cannot read signature
- `SigState`: `0x80090011 (Object was not found)` — no signature exists
All publisher fields remain empty (`APPID://FQBN`, `TokenPublisher`, `ImagePublisher`).

Chrome is signed by Google → all these fields are populated → broker trusts it.

#### Issue C: NGC MakeCredential → `0x80090029 (NTE_NOT_SUPPORTED)`
The actual credential save operation fails. `dsregcmd /status` confirms:
`NgcSet: NO`, `PreReqResult: WillNotProvision`. The NGC key store is not
provisioned on this machine.

Chrome likely uses the **Windows passkey credential provider** (introduced in
Windows 11 22H2+) rather than the legacy NGC path. This provider may have
different requirements or bypass NGC entirely. The gitlab.com passkey created
via Chrome appears in both Chrome's passkey list AND Windows Settings > Passkeys,
confirming Chrome does use the Windows passkey store — but through a different
code path.

### Failure chain summary

```
test_webauthn.exe (unsigned)
  → _CtapSrvGetPublisherFromImageName FAILS (no Authenticode sig)
  → DsrGetJoinInfoNoAccessTokenUrl FAILS (not domain-joined)
  → Ngc MakeCredential attempted anyway
  → NGC reports NTE_NOT_SUPPORTED (not provisioned)
  → Dialog shows "Something went wrong"
  → User cancels → ERROR_CANCELLED returned

chrome.exe (signed by Google)
  → _CtapSrvGetPublisherFromImageName SUCCEEDS
  → DsrGetJoinInfoNoAccessTokenUrl may still fail, but...
  → Chrome may use Windows passkey credential provider (not NGC)
  → Credential saved successfully
```

### Signed python.exe test (v5 — 2026-03-28)

Tested PLATFORM attachment from a pybind11 module loaded by the official
`python.exe`, which is Authenticode-signed by the Python Software Foundation
(DigiCert cert). This isolates whether Issue B (unsigned exe) is the gate.

```
python.exe signature: Valid (CN=Python Software Foundation, DigiCert)
Attachment: PLATFORM
Result: 0x800704C7 (NotAllowedError) — ERROR_CANCELLED
```

**Conclusion:** Code signing is **NOT the gate**. The publisher check warnings
in the event log are informational, not blocking. Even a properly signed
calling process cannot create PLATFORM credentials on this machine.

### Final root cause: NGC not provisioned (0x80090029)

The sole root cause is that the NGC (Next Generation Credential) key store
is not provisioned on this machine:
- `dsregcmd /status` → `NgcSet: NO`, `PreReqResult: WillNotProvision`
- HelloForBusiness log → "Creating a software Windows Hello key with result 0x80090029"
- WebAuthN log → "Ngc MakeCredential completed. Error: 0x80090029. Not supported."

The `WebAuthNAuthenticatorMakeCredential` API with `ATTACHMENT_PLATFORM` always
routes through the NGC path. Since NGC is not provisioned, it always fails with
`NTE_NOT_SUPPORTED`, which the dialog shows as "Something went wrong".

Chrome bypasses this by using the **Windows passkey credential provider**
(introduced in Windows 11 22H2+), which is a separate code path that does not
depend on NGC provisioning. This is why Chrome can create platform passkeys
(visible in both Chrome and Windows Settings > Passkeys) while direct API
callers cannot.

### Definitively ruled out (complete list)

- Options struct version (1, 4, 7, CURRENT_VERSION)
- bRequireResidentKey (TRUE, FALSE)
- RP ID (5 different domains tested)
- ClientData format (raw bytes, JSON with/without origin)
- HWND type (console, foreground, hidden app window with message pump, NULL)
- Cancellation ID (set, not set)
- Exclude credential list (empty, not set)
- Extended fields (all populated for version, all zero)
- Timeout (60s, 120s, 300s)
- **Code signing of calling process** (unsigned exe, signed python.exe)

### Resolution (2026-03-29)

**Fix: NGC re-provisioning.** Steps that resolved the issue:
1. Enable PassportForWork policy: set registry
   `HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\Enabled = 1` (DWORD)
   `HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\DisablePostLogonProvisioning = 0` (DWORD)
2. Stop NGC services: `Stop-Service NgcSvc, NgcCtnrSvc -Force` (admin)
3. Delete NGC container:
   `Remove-Item C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc -Recurse -Force`
4. Restart services, sign out and back in — Windows re-provisions NGC
5. Re-enroll Windows Hello PIN and fingerprint

After this, `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM` works from both the
standalone test executable and the pybind11 native module. Windows Hello
prompts for fingerprint/PIN and successfully creates platform credentials.

### TODO: Integrate PLATFORM attachment

Now that platform auth works, update `_webauthn.cpp` to use
`WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM` (or `ANY`) instead of
`CROSS_PLATFORM`. This enables Windows Hello (fingerprint/PIN) without
needing a phone.
