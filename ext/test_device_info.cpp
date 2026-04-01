/**
 * test_device_info.cpp — v2
 *
 * Uses the v9 WebAuthn API (from webauthn_v9.h) to:
 *   1. List all available authenticators (WebAuthNGetAuthenticatorList)
 *   2. Create a credential with hint "hybrid" to force phone/QR dialog
 *   3. Dump all device info from the response (AAGUID, transports, attestation)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Use our local v9 header instead of the SDK's older v7 header
#include "webauthn_v9.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <thread>
#include <atomic>
#include <string>

#pragma comment(lib, "webauthn.lib")

// ---------------------------------------------------------------------------
// Hidden window
// ---------------------------------------------------------------------------
static const wchar_t* HIDDEN_WND_CLASS = L"DevInfoTestWindow";
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
    HWND hwnd = CreateWindowExW(WS_EX_APPWINDOW, HIDDEN_WND_CLASS, L"DevInfo Helper",
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

void print_guid_from_bytes(const char* label, const BYTE* data) {
    std::cout << label;
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        if (i == 3 || i == 5 || i == 7 || i == 9) std::cout << "-";
    }
    std::cout << std::dec << std::endl;
}

void print_transport_flags(DWORD transport) {
    std::cout << "  Transport flags:         0x" << std::hex << transport << std::dec << std::endl;
    if (transport & WEBAUTHN_CTAP_TRANSPORT_USB)       std::cout << "    -> USB" << std::endl;
    if (transport & WEBAUTHN_CTAP_TRANSPORT_NFC)       std::cout << "    -> NFC" << std::endl;
    if (transport & WEBAUTHN_CTAP_TRANSPORT_BLE)       std::cout << "    -> BLE" << std::endl;
    if (transport & WEBAUTHN_CTAP_TRANSPORT_INTERNAL)  std::cout << "    -> INTERNAL (platform)" << std::endl;
    if (transport & WEBAUTHN_CTAP_TRANSPORT_HYBRID)    std::cout << "    -> HYBRID (caBLE/phone)" << std::endl;
}

void parse_authenticator_data(const BYTE* authData, DWORD authDataLen) {
    if (authDataLen < 37) {
        std::cout << "  AuthData too short" << std::endl;
        return;
    }
    print_hex("  RP ID hash:              ", authData, 32);
    BYTE flags = authData[32];
    std::cout << "  Flags:                   0x" << std::hex << (int)flags << std::dec << std::endl;
    std::cout << "    UP (user present):     " << ((flags & 0x01) ? "YES" : "NO") << std::endl;
    std::cout << "    UV (user verified):    " << ((flags & 0x04) ? "YES" : "NO") << std::endl;
    std::cout << "    AT (attested cred):    " << ((flags & 0x40) ? "YES" : "NO") << std::endl;

    DWORD counter = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36];
    std::cout << "  Sign counter:            " << counter << std::endl;

    if ((flags & 0x40) && authDataLen >= 55) {
        print_guid_from_bytes("  AAGUID:                  ", authData + 37);
        bool allZero = true;
        for (int i = 0; i < 16; i++) if (authData[37 + i] != 0) { allZero = false; break; }
        if (allZero)
            std::cout << "  AAGUID note:             ALL ZEROS (privacy mode)" << std::endl;

        WORD credIdLen = (authData[53] << 8) | authData[54];
        std::cout << "  Credential ID length:    " << credIdLen << " bytes" << std::endl;
    }
}

// ---------------------------------------------------------------------------
// Step 1: Enumerate authenticators (API v9)
// ---------------------------------------------------------------------------
void list_authenticators() {
    std::cout << "========== AVAILABLE AUTHENTICATORS (v9 API) ==========" << std::endl;

    // Dynamically load the v9 function (not in our SDK's .lib)
    typedef HRESULT (WINAPI *PFN_GetAuthenticatorList)(
        PCWEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS,
        PWEBAUTHN_AUTHENTICATOR_DETAILS_LIST*);
    typedef void (WINAPI *PFN_FreeAuthenticatorList)(
        PWEBAUTHN_AUTHENTICATOR_DETAILS_LIST);

    HMODULE hMod = LoadLibraryW(L"webauthn.dll");
    if (!hMod) {
        std::cerr << "  Failed to load webauthn.dll" << std::endl;
        return;
    }

    auto pfnGet = (PFN_GetAuthenticatorList)GetProcAddress(hMod, "WebAuthNGetAuthenticatorList");
    auto pfnFree = (PFN_FreeAuthenticatorList)GetProcAddress(hMod, "WebAuthNFreeAuthenticatorList");

    if (!pfnGet || !pfnFree) {
        std::cout << "  WebAuthNGetAuthenticatorList not available (API < 9)" << std::endl;
        FreeLibrary(hMod);
        return;
    }

    WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS opts = { 0 };
    opts.dwVersion = WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS_CURRENT_VERSION;

    PWEBAUTHN_AUTHENTICATOR_DETAILS_LIST pList = nullptr;
    HRESULT hr = pfnGet(&opts, &pList);

    if (FAILED(hr)) {
        std::cerr << "  WebAuthNGetAuthenticatorList failed: 0x"
                  << std::hex << (unsigned long)hr << std::dec << std::endl;
        FreeLibrary(hMod);
        return;
    }

    if (!pList || pList->cAuthenticatorDetails == 0) {
        std::cout << "  No authenticators found." << std::endl;
    } else {
        std::cout << "  Found " << pList->cAuthenticatorDetails << " authenticator(s):" << std::endl;
        for (DWORD i = 0; i < pList->cAuthenticatorDetails; i++) {
            PWEBAUTHN_AUTHENTICATOR_DETAILS det = pList->ppAuthenticatorDetails[i];
            std::cout << std::endl;
            std::cout << "  [" << i << "] Name: ";
            if (det->pwszAuthenticatorName) std::wcout << det->pwszAuthenticatorName;
            else std::cout << "(null)";
            std::cout << std::endl;

            std::cout << "      ID:   ";
            print_hex("", det->pbAuthenticatorId, det->cbAuthenticatorId);

            std::cout << "      Logo:  " << det->cbAuthenticatorLogo << " bytes";
            if (det->cbAuthenticatorLogo > 0) std::cout << " (SVG)";
            std::cout << std::endl;

            std::cout << "      Locked: " << (det->bLocked ? "YES" : "NO") << std::endl;
        }
    }

    pfnFree(pList);
    FreeLibrary(hMod);
}

// ---------------------------------------------------------------------------
// Step 2: MakeCredential with hybrid hint (API v8+)
// ---------------------------------------------------------------------------
int main() {
    srand((unsigned)time(nullptr));
    std::cout << "=== WebAuthn Device Info Test v2 (API v9 header) ===" << std::endl << std::endl;

    DWORD apiVersion = WebAuthNGetApiVersionNumber();
    std::cout << "WebAuthN API version: " << apiVersion << std::endl << std::endl;

    // --- List authenticators ---
    list_authenticators();

    // --- Create credential with hybrid hint ---
    std::cout << std::endl << "========== MAKE CREDENTIAL (no hint, hidden app window) ==========" << std::endl;

    HWND hwnd = create_hidden_window();
    if (!hwnd) {
        std::cerr << "ERROR: Failed to create window" << std::endl;
        destroy_hidden_window();
        return 1;
    }
    std::cout << "Using hidden app HWND: 0x" << std::hex << (uintptr_t)hwnd << std::dec << std::endl;

    time_t now = time(nullptr);
    BYTE userId[16] = { 0 };
    memcpy(userId, &now, sizeof(now));
    userId[8] = (BYTE)(rand() & 0xFF);

    WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = { 0 };
    rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpInfo.pwszId = L"credentials.dotenv-webauthn.com";
    rpInfo.pwszName = L"Dotenv WebAuthn Crypt";

    WEBAUTHN_USER_ENTITY_INFORMATION userInfo = { 0 };
    userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
    userInfo.cbId = 16;
    userInfo.pbId = userId;
    userInfo.pwszName = L"device_info_test";
    userInfo.pwszDisplayName = L"Device Info Test";

    WEBAUTHN_COSE_CREDENTIAL_PARAMETER alg = { 0 };
    alg.dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
    alg.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    alg.lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pubKeyParams = { 1, &alg };

    BYTE rawChallenge[32];
    memset(rawChallenge, 0xAA, 32);
    WEBAUTHN_CLIENT_DATA clientData = { 0 };
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = 32;
    clientData.pbClientDataJSON = rawChallenge;
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    // Build options with version 8 to use credential hints
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options = { 0 };
    options.dwVersion = 8;  // v8 has ppwszCredentialHints
    options.dwTimeoutMilliseconds = 300000;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
    options.bRequireResidentKey = FALSE;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT;
    options.dwFlags = 0;

    // v2: cancellation
    GUID cancellationId = { 0 };
    if (SUCCEEDED(WebAuthNGetCancellationId(&cancellationId))) {
        options.pCancellationId = &cancellationId;
    }

    // v3: empty exclude list
    WEBAUTHN_CREDENTIAL_LIST excludeList = { 0 };
    options.pExcludeCredentialList = &excludeList;

    // v4
    options.dwEnterpriseAttestation = WEBAUTHN_ENTERPRISE_ATTESTATION_NONE;
    options.dwLargeBlobSupport = WEBAUTHN_LARGE_BLOB_SUPPORT_NONE;
    options.bPreferResidentKey = FALSE;

    // v5
    options.bBrowserInPrivateMode = FALSE;

    // v6
    options.bEnablePrf = FALSE;

    // v7
    options.pLinkedDevice = nullptr;
    options.cbJsonExt = 0;
    options.pbJsonExt = nullptr;

    // v8: no hints — see if 3-way chooser appears without hidden window
    options.pPRFGlobalEval = nullptr;
    options.cCredentialHints = 0;
    options.ppwszCredentialHints = nullptr;
    options.bThirdPartyPayment = FALSE;

    // v9 fields — not targeting a specific authenticator
    options.dwVersion = 9;
    options.pwszRemoteWebOrigin = nullptr;
    options.cbPublicKeyCredentialCreationOptionsJSON = 0;
    options.pbPublicKeyCredentialCreationOptionsJSON = nullptr;
    options.cbAuthenticatorId = 0;
    options.pbAuthenticatorId = nullptr;

    std::cout << "  Attachment: ANY" << std::endl;
    std::cout << "  Hints: [] (none)" << std::endl;
    std::cout << "  Attestation: DIRECT" << std::endl;
    std::cout << "  Options version: 9" << std::endl;
    std::cout << std::endl << "  Calling WebAuthNAuthenticatorMakeCredential..." << std::endl;
    std::cout << "  Please authenticate with your phone when the dialog appears." << std::endl << std::endl;

    PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = nullptr;
    HRESULT hr = WebAuthNAuthenticatorMakeCredential(
        hwnd, &rpInfo, &userInfo, &pubKeyParams, &clientData, &options, &pAttestation
    );

    if (FAILED(hr)) {
        PCWSTR errName = WebAuthNGetErrorName(hr);
        std::cerr << "MakeCredential FAILED: 0x" << std::hex << (unsigned long)hr << std::dec;
        if (errName) std::wcerr << L" (" << errName << L")";
        std::cerr << std::endl;
        destroy_hidden_window();
        return 1;
    }

    std::cout << "========== SUCCESS ==========" << std::endl << std::endl;

    std::cout << "--- Attestation fields ---" << std::endl;
    std::cout << "  dwVersion:               " << pAttestation->dwVersion << std::endl;
    std::cout << "  Format type:             ";
    if (pAttestation->pwszFormatType) std::wcout << pAttestation->pwszFormatType;
    else std::cout << "(null)";
    std::cout << std::endl;
    std::cout << "  Credential ID size:      " << pAttestation->cbCredentialId << " bytes" << std::endl;
    print_hex("  Credential ID:           ", pAttestation->pbCredentialId, pAttestation->cbCredentialId);
    std::cout << "  AuthenticatorData size:  " << pAttestation->cbAuthenticatorData << " bytes" << std::endl;
    std::cout << "  AttestationObject size:  " << pAttestation->cbAttestationObject << " bytes" << std::endl;
    print_transport_flags(pAttestation->dwUsedTransport);

    if (pAttestation->dwVersion >= 3) {
        std::cout << "  bEpAtt:                  " << (pAttestation->bEpAtt ? "TRUE" : "FALSE") << std::endl;
        std::cout << "  bLargeBlobSupported:     " << (pAttestation->bLargeBlobSupported ? "TRUE" : "FALSE") << std::endl;
        std::cout << "  bResidentKey:            " << (pAttestation->bResidentKey ? "TRUE" : "FALSE") << std::endl;
    }

    std::cout << std::endl << "--- AuthenticatorData ---" << std::endl;
    parse_authenticator_data(pAttestation->pbAuthenticatorData, pAttestation->cbAuthenticatorData);

    if (pAttestation->cbAttestationObject > 0) {
        std::ofstream outfile("test_attestation_object.bin", std::ios::binary);
        outfile.write(reinterpret_cast<const char*>(pAttestation->pbAttestationObject),
                      pAttestation->cbAttestationObject);
        outfile.close();
        std::cout << std::endl << "  Saved attestation object (" << pAttestation->cbAttestationObject
                  << " bytes) to test_attestation_object.bin" << std::endl;
    }

    WebAuthNFreeCredentialAttestation(pAttestation);
    destroy_hidden_window();
    std::cout << std::endl << "=== Done ===" << std::endl;
    std::cout << "Look up AAGUID at: https://passkeydeveloper.github.io/passkey-authenticator-aaguids/" << std::endl;
    return 0;
}
