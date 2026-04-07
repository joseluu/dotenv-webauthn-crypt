/**
 * test_hmac_secret.cpp
 *
 * Standalone test to check hmac-secret extension availability on authenticators.
 *
 * Two-phase test:
 *   Phase 1: MakeCredential with hmac-secret extension => check if device reports support
 *   Phase 2: GetAssertion with HMAC salt values => check if device returns HMAC output
 *
 * Build (from Git Bash with vcvars or response files):
 *   cl /EHsc /std:c++17 test_hmac_secret.cpp /I. /link webauthn.lib user32.lib /OUT:test_hmac_secret.exe
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "webauthn_v9.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <ctime>
#include <cstring>
#include <thread>
#include <atomic>

#pragma comment(lib, "webauthn.lib")
#pragma comment(lib, "user32.lib")

// ---------------------------------------------------------------------------
// Hidden window (needed for WebAuthn dialog)
// ---------------------------------------------------------------------------
static const wchar_t* HIDDEN_WND_CLASS = L"HmacSecretTestWindow";
static std::atomic<HWND> g_hiddenHwnd{nullptr};
static std::atomic<bool> g_msgLoopReady{false};

LRESULT CALLBACK HiddenWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void message_loop_thread() {
    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = HiddenWndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = HIDDEN_WND_CLASS;
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowExW(WS_EX_APPWINDOW, HIDDEN_WND_CLASS, L"HmacSecret Helper",
        WS_POPUP | WS_VISIBLE, 0, 0, 0, 0, nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
    g_hiddenHwnd.store(hwnd);
    g_msgLoopReady.store(true);
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessage(&msg); }
}

HWND create_hidden_window() {
    std::thread t(message_loop_thread);
    t.detach();
    while (!g_msgLoopReady.load()) Sleep(10);
    return g_hiddenHwnd.load();
}

void destroy_hidden_window() {
    HWND hwnd = g_hiddenHwnd.load();
    if (hwnd) { PostMessage(hwnd, WM_CLOSE, 0, 0); Sleep(100); }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
void print_hex(const char* label, const BYTE* data, DWORD len) {
    std::cout << label;
    for (DWORD i = 0; i < len; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    std::cout << std::dec << std::endl;
}

std::string hresult_str(HRESULT hr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(8) << std::setfill('0') << (unsigned long)hr;
    PCWSTR errName = WebAuthNGetErrorName(hr);
    if (errName) {
        char buf[256];
        WideCharToMultiByte(CP_UTF8, 0, errName, -1, buf, sizeof(buf), NULL, NULL);
        oss << " (" << buf << ")";
    }
    return oss.str();
}

void print_transport_flags(DWORD transport) {
    std::cout << "  Transport flags:         0x" << std::hex << transport << std::dec << std::endl;
    if (transport & WEBAUTHN_CTAP_TRANSPORT_USB)       std::cout << "    -> USB" << std::endl;
    if (transport & WEBAUTHN_CTAP_TRANSPORT_NFC)       std::cout << "    -> NFC" << std::endl;
    if (transport & WEBAUTHN_CTAP_TRANSPORT_BLE)       std::cout << "    -> BLE" << std::endl;
    if (transport & WEBAUTHN_CTAP_TRANSPORT_INTERNAL)  std::cout << "    -> INTERNAL (platform)" << std::endl;
    if (transport & WEBAUTHN_CTAP_TRANSPORT_HYBRID)    std::cout << "    -> HYBRID (caBLE/phone)" << std::endl;
}

// ---------------------------------------------------------------------------
// Phase 1: MakeCredential with hmac-secret extension
// ---------------------------------------------------------------------------
struct CredentialResult {
    bool success;
    std::vector<BYTE> credentialId;
    bool hmacSecretCreated;
    bool prfEnabled;
    DWORD usedTransport;
};

CredentialResult phase1_make_credential(HWND hwnd) {
    CredentialResult result = { false, {}, false, false, 0 };

    std::cout << "========== PHASE 1: MakeCredential with hmac-secret ==========" << std::endl;

    // RP
    WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = { 0 };
    rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpInfo.pwszId = L"hmac-secret-test.local";
    rpInfo.pwszName = L"HMAC-Secret Test";

    // User (unique per run)
    time_t now = time(nullptr);
    BYTE userId[16] = { 0 };
    memcpy(userId, &now, sizeof(now));
    userId[8] = (BYTE)(rand() & 0xFF);

    WEBAUTHN_USER_ENTITY_INFORMATION userInfo = { 0 };
    userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
    userInfo.cbId = 16;
    userInfo.pbId = userId;
    userInfo.pwszName = L"hmac_test_user";
    userInfo.pwszDisplayName = L"HMAC Test User";

    // Algorithm
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER alg = { 0 };
    alg.dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
    alg.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    alg.lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pubKeyParams = { 1, &alg };

    // Client data (challenge)
    BYTE challenge[32];
    memset(challenge, 0xAA, 32);
    WEBAUTHN_CLIENT_DATA clientData = { 0 };
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = 32;
    clientData.pbClientDataJSON = challenge;
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    // --- hmac-secret extension: request it ---
    BOOL hmacSecretTrue = TRUE;
    WEBAUTHN_EXTENSION hmacExt = { 0 };
    hmacExt.pwszExtensionIdentifier = WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET;
    hmacExt.cbExtension = sizeof(BOOL);
    hmacExt.pvExtension = &hmacSecretTrue;

    // Options
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options = { 0 };
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 120000;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
    options.bRequireResidentKey = FALSE;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT;

    // Attach hmac-secret extension
    options.Extensions.cExtensions = 1;
    options.Extensions.pExtensions = &hmacExt;

    // v2: cancellation
    GUID cancellationId = { 0 };
    if (SUCCEEDED(WebAuthNGetCancellationId(&cancellationId))) {
        options.pCancellationId = &cancellationId;
    }

    // v3
    WEBAUTHN_CREDENTIAL_LIST excludeList = { 0 };
    options.pExcludeCredentialList = &excludeList;

    // v4
    options.dwEnterpriseAttestation = WEBAUTHN_ENTERPRISE_ATTESTATION_NONE;
    options.dwLargeBlobSupport = WEBAUTHN_LARGE_BLOB_SUPPORT_NONE;
    options.bPreferResidentKey = FALSE;

    // v5
    options.bBrowserInPrivateMode = FALSE;

    // v6 — also request PRF
    options.bEnablePrf = TRUE;

    // v7
    options.pLinkedDevice = nullptr;
    options.cbJsonExt = 0;
    options.pbJsonExt = nullptr;

    // v8
    options.pPRFGlobalEval = nullptr;
    options.cCredentialHints = 0;
    options.ppwszCredentialHints = nullptr;
    options.bThirdPartyPayment = FALSE;

    // v9
    options.pwszRemoteWebOrigin = nullptr;
    options.cbPublicKeyCredentialCreationOptionsJSON = 0;
    options.pbPublicKeyCredentialCreationOptionsJSON = nullptr;
    options.cbAuthenticatorId = 0;
    options.pbAuthenticatorId = nullptr;

    std::cout << "  Extensions requested:    hmac-secret=true, enablePrf=true" << std::endl;
    std::cout << "  Attachment:              ANY" << std::endl;
    std::cout << "  Attestation:             DIRECT" << std::endl;
    std::cout << std::endl;
    std::cout << "  Calling MakeCredential... (authenticate when prompted)" << std::endl << std::endl;

    PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = nullptr;
    HRESULT hr = WebAuthNAuthenticatorMakeCredential(
        hwnd, &rpInfo, &userInfo, &pubKeyParams, &clientData, &options, &pAttestation
    );

    if (FAILED(hr)) {
        std::cerr << "  MakeCredential FAILED: " << hresult_str(hr) << std::endl;
        return result;
    }

    std::cout << "  MakeCredential SUCCESS" << std::endl;
    std::cout << "  Attestation version:     " << pAttestation->dwVersion << std::endl;
    std::cout << "  Credential ID size:      " << pAttestation->cbCredentialId << " bytes" << std::endl;
    print_hex("  Credential ID:           ", pAttestation->pbCredentialId, pAttestation->cbCredentialId);
    print_transport_flags(pAttestation->dwUsedTransport);

    result.credentialId.assign(
        pAttestation->pbCredentialId,
        pAttestation->pbCredentialId + pAttestation->cbCredentialId);
    result.usedTransport = pAttestation->dwUsedTransport;

    // Check hmac-secret in output extensions
    std::cout << std::endl << "  --- Extension outputs ---" << std::endl;
    std::cout << "  Extension count:         " << pAttestation->Extensions.cExtensions << std::endl;
    for (DWORD i = 0; i < pAttestation->Extensions.cExtensions; i++) {
        PWEBAUTHN_EXTENSION ext = &pAttestation->Extensions.pExtensions[i];
        char extName[256];
        WideCharToMultiByte(CP_UTF8, 0, ext->pwszExtensionIdentifier, -1, extName, sizeof(extName), NULL, NULL);
        std::cout << "  Extension[" << i << "]:            " << extName
                  << " (size=" << ext->cbExtension << ")" << std::endl;

        if (wcscmp(ext->pwszExtensionIdentifier, WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET) == 0) {
            if (ext->cbExtension == sizeof(BOOL) && ext->pvExtension) {
                BOOL val = *(BOOL*)ext->pvExtension;
                result.hmacSecretCreated = (val != FALSE);
                std::cout << "    hmac-secret result:    " << (val ? "TRUE (SUPPORTED!)" : "FALSE") << std::endl;
            }
        }
    }

    // Check PRF enabled (attestation v5+)
    if (pAttestation->dwVersion >= 5) {
        result.prfEnabled = (pAttestation->bPrfEnabled != FALSE);
        std::cout << "  bPrfEnabled:             " << (pAttestation->bPrfEnabled ? "TRUE" : "FALSE") << std::endl;
    } else {
        std::cout << "  bPrfEnabled:             (not available, attestation version < 5)" << std::endl;
    }

    // Check pHmacSecret in attestation (v7+)
    if (pAttestation->dwVersion >= 7) {
        if (pAttestation->pHmacSecret) {
            std::cout << "  pHmacSecret (v7):        present" << std::endl;
            std::cout << "    first size:            " << pAttestation->pHmacSecret->cbFirst << std::endl;
            if (pAttestation->pHmacSecret->cbFirst > 0)
                print_hex("    first:                 ", pAttestation->pHmacSecret->pbFirst, pAttestation->pHmacSecret->cbFirst);
            std::cout << "    second size:           " << pAttestation->pHmacSecret->cbSecond << std::endl;
            if (pAttestation->pHmacSecret->cbSecond > 0)
                print_hex("    second:                ", pAttestation->pHmacSecret->pbSecond, pAttestation->pHmacSecret->cbSecond);
        } else {
            std::cout << "  pHmacSecret (v7):        NULL" << std::endl;
        }
    }

    result.success = true;
    WebAuthNFreeCredentialAttestation(pAttestation);
    return result;
}

// ---------------------------------------------------------------------------
// Phase 2: GetAssertion with HMAC salt to retrieve hmac-secret output
// ---------------------------------------------------------------------------
void phase2_get_assertion(HWND hwnd, const CredentialResult& cred) {
    std::cout << std::endl << "========== PHASE 2: GetAssertion with HMAC salt ==========" << std::endl;

    if (!cred.success || cred.credentialId.empty()) {
        std::cerr << "  Skipping — no credential from Phase 1" << std::endl;
        return;
    }

    // Challenge
    BYTE challenge[32];
    memset(challenge, 0xBB, 32);
    WEBAUTHN_CLIENT_DATA clientData = { 0 };
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = 32;
    clientData.pbClientDataJSON = challenge;
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    // Allowed credential
    WEBAUTHN_CREDENTIAL_EX allowedCred = { 0 };
    allowedCred.dwVersion = WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION;
    allowedCred.cbId = (DWORD)cred.credentialId.size();
    allowedCred.pbId = const_cast<BYTE*>(cred.credentialId.data());
    allowedCred.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    allowedCred.dwTransports = cred.usedTransport;

    PWEBAUTHN_CREDENTIAL_EX ppAllowed[1] = { &allowedCred };
    WEBAUTHN_CREDENTIAL_LIST allowList = { 0 };
    allowList.cCredentials = 1;
    allowList.ppCredentials = ppAllowed;

    // HMAC salt values — 32-byte salt
    BYTE salt1[WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH];
    memset(salt1, 0x42, WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH);

    WEBAUTHN_HMAC_SECRET_SALT globalSalt = { 0 };
    globalSalt.cbFirst = WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH;
    globalSalt.pbFirst = salt1;
    globalSalt.cbSecond = 0;
    globalSalt.pbSecond = nullptr;

    WEBAUTHN_HMAC_SECRET_SALT_VALUES saltValues = { 0 };
    saltValues.pGlobalHmacSalt = &globalSalt;
    saltValues.cCredWithHmacSecretSaltList = 0;
    saltValues.pCredWithHmacSecretSaltList = nullptr;

    // Options
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options = { 0 };
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 120000;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwFlags = WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG;

    // v3: cancellation
    GUID cancellationId = { 0 };
    if (SUCCEEDED(WebAuthNGetCancellationId(&cancellationId))) {
        options.pCancellationId = &cancellationId;
    }

    // v4: allow list
    options.pAllowCredentialList = &allowList;

    // v5
    options.dwCredLargeBlobOperation = WEBAUTHN_CRED_LARGE_BLOB_STATUS_NONE;
    options.cbCredLargeBlob = 0;
    options.pbCredLargeBlob = nullptr;

    // v6: HMAC salt
    options.pHmacSecretSaltValues = &saltValues;
    options.bBrowserInPrivateMode = FALSE;

    // v7
    options.pLinkedDevice = nullptr;
    options.bAutoFill = FALSE;
    options.cbJsonExt = 0;
    options.pbJsonExt = nullptr;

    // v8
    options.cCredentialHints = 0;
    options.ppwszCredentialHints = nullptr;

    // v9
    options.pwszRemoteWebOrigin = nullptr;
    options.cbPublicKeyCredentialRequestOptionsJSON = 0;
    options.pbPublicKeyCredentialRequestOptionsJSON = nullptr;
    options.cbAuthenticatorId = 0;
    options.pbAuthenticatorId = nullptr;

    print_hex("  Salt (first):            ", salt1, WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH);
    std::cout << "  dwFlags:                 0x" << std::hex << options.dwFlags << std::dec
              << " (HMAC_SECRET_VALUES_FLAG)" << std::endl;
    std::cout << std::endl;
    std::cout << "  Calling GetAssertion... (authenticate again when prompted)" << std::endl << std::endl;

    PWEBAUTHN_ASSERTION pAssertion = nullptr;
    HRESULT hr = WebAuthNAuthenticatorGetAssertion(
        hwnd, L"hmac-secret-test.local", &clientData, &options, &pAssertion
    );

    if (FAILED(hr)) {
        std::cerr << "  GetAssertion FAILED: " << hresult_str(hr) << std::endl;
        return;
    }

    std::cout << "  GetAssertion SUCCESS" << std::endl;
    std::cout << "  Assertion version:       " << pAssertion->dwVersion << std::endl;
    std::cout << "  Signature size:          " << pAssertion->cbSignature << " bytes" << std::endl;

    // Check extensions
    std::cout << std::endl << "  --- Extension outputs ---" << std::endl;
    std::cout << "  Extension count:         " << pAssertion->Extensions.cExtensions << std::endl;
    for (DWORD i = 0; i < pAssertion->Extensions.cExtensions; i++) {
        PWEBAUTHN_EXTENSION ext = &pAssertion->Extensions.pExtensions[i];
        char extName[256];
        WideCharToMultiByte(CP_UTF8, 0, ext->pwszExtensionIdentifier, -1, extName, sizeof(extName), NULL, NULL);
        std::cout << "  Extension[" << i << "]:            " << extName
                  << " (size=" << ext->cbExtension << ")" << std::endl;
    }

    // Check pHmacSecret in assertion (v3+)
    std::cout << std::endl << "  --- HMAC-Secret output ---" << std::endl;
    if (pAssertion->dwVersion >= 3 && pAssertion->pHmacSecret) {
        std::cout << "  pHmacSecret:             PRESENT" << std::endl;
        std::cout << "    first size:            " << pAssertion->pHmacSecret->cbFirst << " bytes" << std::endl;
        if (pAssertion->pHmacSecret->cbFirst > 0) {
            print_hex("    first (HMAC output):   ", pAssertion->pHmacSecret->pbFirst, pAssertion->pHmacSecret->cbFirst);
        }
        std::cout << "    second size:           " << pAssertion->pHmacSecret->cbSecond << " bytes" << std::endl;
        if (pAssertion->pHmacSecret->cbSecond > 0) {
            print_hex("    second (HMAC output):  ", pAssertion->pHmacSecret->pbSecond, pAssertion->pHmacSecret->cbSecond);
        }
        std::cout << std::endl << "  *** HMAC-SECRET IS WORKING on this device! ***" << std::endl;
    } else {
        std::cout << "  pHmacSecret:             NULL (not returned)" << std::endl;
        if (pAssertion->dwVersion < 3) {
            std::cout << "  (assertion version " << pAssertion->dwVersion << " < 3, field not available)" << std::endl;
        } else {
            std::cout << "  => Device did NOT return HMAC-secret output." << std::endl;
        }
    }

    // Transport used
    if (pAssertion->dwVersion >= 4) {
        print_transport_flags(pAssertion->dwUsedTransport);
    }

    WebAuthNFreeAssertion(pAssertion);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main() {
    srand((unsigned)time(nullptr));
    std::cout << "=== HMAC-Secret Extension Availability Test ===" << std::endl << std::endl;

    DWORD apiVersion = WebAuthNGetApiVersionNumber();
    std::cout << "WebAuthN API version:      " << apiVersion << std::endl;

    if (apiVersion < 2) {
        std::cerr << "ERROR: API version " << apiVersion << " too old — hmac-secret requires API >= 2" << std::endl;
        return 1;
    }

    BOOL platformAvail = FALSE;
    WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&platformAvail);
    std::cout << "Platform authenticator:    " << (platformAvail ? "YES" : "NO") << std::endl;
    std::cout << std::endl;

    HWND hwnd = create_hidden_window();
    if (!hwnd) {
        std::cerr << "ERROR: Failed to create window" << std::endl;
        return 1;
    }
    std::cout << "Using hidden app HWND:     0x" << std::hex << (uintptr_t)hwnd << std::dec << std::endl << std::endl;

    // Phase 1: Create credential with hmac-secret
    CredentialResult cred = phase1_make_credential(hwnd);

    if (!cred.success) {
        std::cerr << std::endl << "Phase 1 failed — cannot proceed to Phase 2." << std::endl;
        destroy_hidden_window();
        return 1;
    }

    // Summary after Phase 1
    std::cout << std::endl << "  --- Phase 1 Summary ---" << std::endl;
    std::cout << "  hmac-secret created:     " << (cred.hmacSecretCreated ? "YES" : "NO") << std::endl;
    std::cout << "  PRF enabled:             " << (cred.prfEnabled ? "YES" : "NO") << std::endl;

    // Phase 2: GetAssertion with salt
    phase2_get_assertion(hwnd, cred);

    // Final summary
    std::cout << std::endl << "========== SUMMARY ==========" << std::endl;
    std::cout << "  API version:             " << apiVersion << std::endl;
    std::cout << "  hmac-secret (Phase 1):   " << (cred.hmacSecretCreated ? "SUPPORTED" : "NOT REPORTED") << std::endl;
    std::cout << "  PRF enabled (Phase 1):   " << (cred.prfEnabled ? "YES" : "NO") << std::endl;
    std::cout << "  (Phase 2 results above show if HMAC output was actually returned)" << std::endl;

    destroy_hidden_window();
    std::cout << std::endl << "=== Done ===" << std::endl;
    return 0;
}
