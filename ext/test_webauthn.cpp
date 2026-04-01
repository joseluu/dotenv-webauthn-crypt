#include <windows.h>
#include <webauthn.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <iomanip>
#include <ctime>
#include <thread>
#include <atomic>

#pragma comment(lib, "webauthn.lib")

// ---------------------------------------------------------------------------
// Hidden window (kept from v3 — provides a valid HWND)
// ---------------------------------------------------------------------------
static const wchar_t* HIDDEN_WND_CLASS = L"WebAuthnHiddenWindow";
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
    HWND hwnd = CreateWindowExW(WS_EX_APPWINDOW, HIDDEN_WND_CLASS, L"WebAuthn Helper",
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
void print_hr(const char* label, HRESULT hr) {
    std::cerr << label << " HRESULT: 0x" << std::hex << std::setw(8) << std::setfill('0') << (unsigned long)hr << std::dec;
    PCWSTR errName = WebAuthNGetErrorName(hr);
    if (errName) std::wcerr << L"  (" << errName << L")";
    std::cerr << std::endl;
}

void print_separator(const char* title) {
    std::cout << std::endl << "========== " << title << " ==========" << std::endl;
}

void print_guid(const char* label, const GUID& g) {
    std::cout << label << std::hex << std::setfill('0')
        << std::setw(8) << g.Data1 << "-"
        << std::setw(4) << g.Data2 << "-"
        << std::setw(4) << g.Data3 << "-";
    for (int i = 0; i < 2; i++) std::cout << std::setw(2) << (int)g.Data4[i];
    std::cout << "-";
    for (int i = 2; i < 8; i++) std::cout << std::setw(2) << (int)g.Data4[i];
    std::cout << std::dec << std::endl;
}

// ---------------------------------------------------------------------------
// Test: Browser-style MakeCredential (VERSION_7, cancellation ID, JSON clientData)
// ---------------------------------------------------------------------------
bool try_browser_style(HWND hwnd, const char* description, DWORD optionsVersion,
                       bool useCancellationId, bool useJsonClientData,
                       BOOL residentKey) {
    print_separator(description);

    // Fresh user ID
    time_t now = time(nullptr);
    BYTE userId[16];
    memset(userId, 0, 16);
    memcpy(userId, &now, sizeof(now));
    userId[8] = (BYTE)(rand() & 0xFF);
    userId[9] = (BYTE)(rand() & 0xFF);

    // RP Info
    WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = { 0 };
    rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpInfo.pwszId = L"credentials.dotenv-webauthn.com";
    rpInfo.pwszName = L"Dotenv WebAuthn Crypt";

    // User Info
    WEBAUTHN_USER_ENTITY_INFORMATION userInfo = { 0 };
    userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
    userInfo.cbId = 16;
    userInfo.pbId = userId;
    userInfo.pwszName = L"test_user";
    userInfo.pwszDisplayName = L"Test User";

    // Credential Parameters
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER alg = { 0 };
    alg.dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
    alg.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    alg.lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pubKeyParams = { 1, &alg };

    // Client Data — either proper JSON or raw bytes
    std::string jsonStr = "{\"type\":\"webauthn.create\",\"challenge\":\"dGVzdC1jaGFsbGVuZ2U\",\"origin\":\"https://credentials.dotenv-webauthn.com\",\"crossOrigin\":false}";
    BYTE rawChallenge[32];
    memset(rawChallenge, 0xEE, 32);

    WEBAUTHN_CLIENT_DATA clientData = { 0 };
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;
    if (useJsonClientData) {
        clientData.cbClientDataJSON = (DWORD)jsonStr.size();
        clientData.pbClientDataJSON = (PBYTE)jsonStr.c_str();
    } else {
        clientData.cbClientDataJSON = 32;
        clientData.pbClientDataJSON = rawChallenge;
    }

    // Cancellation ID (like Firefox/Chromium)
    GUID cancellationId = { 0 };
    bool hasCancellation = false;
    if (useCancellationId) {
        HRESULT hrCancel = WebAuthNGetCancellationId(&cancellationId);
        if (SUCCEEDED(hrCancel)) {
            hasCancellation = true;
            print_guid("  Cancellation ID:      ", cancellationId);
        } else {
            std::cout << "  Cancellation ID:      FAILED to obtain (hr=0x"
                      << std::hex << hrCancel << std::dec << ")" << std::endl;
        }
    }

    // Empty exclude list (like browsers send for new credentials)
    WEBAUTHN_CREDENTIAL_LIST excludeList = { 0 };
    excludeList.cCredentials = 0;
    excludeList.ppCredentials = nullptr;

    // Make Credential Options — populate ALL fields for the declared version
    // VERSION_7 layout (from webauthn.h):
    //   v1: timeout, CredentialList, Extensions, AuthenticatorAttachment,
    //       bRequireResidentKey, UserVerification, AttestationConveyance
    //   v2: + pCancellationId
    //   v3: + pExcludeCredentialList
    //   v4: + dwEnterpriseAttestation, dwLargeBlobSupport, bPreferResidentKey
    //   v5: + bBrowserInPrivateMode
    //   v6: + bEnablePrf
    //   v7: + pLinkedDevice, cbJsonExt, pbJsonExt

    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options = { 0 };
    options.dwVersion = optionsVersion;
    options.dwTimeoutMilliseconds = 300000; // 5 minutes like Chromium
    // v1 fields
    options.CredentialList.cCredentials = 0;
    options.CredentialList.pCredentials = nullptr;
    options.Extensions.cExtensions = 0;
    options.Extensions.pExtensions = nullptr;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
    options.bRequireResidentKey = residentKey;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;

    // v2+: cancellation ID
    if (optionsVersion >= 2 && hasCancellation) {
        options.pCancellationId = &cancellationId;
    }
    // v3+: exclude credential list
    if (optionsVersion >= 3) {
        options.pExcludeCredentialList = &excludeList;
    }
    // v4+: enterprise attestation, large blob, prefer resident key
    if (optionsVersion >= 4) {
        options.dwEnterpriseAttestation = WEBAUTHN_ENTERPRISE_ATTESTATION_NONE;
        options.dwLargeBlobSupport = WEBAUTHN_LARGE_BLOB_SUPPORT_NONE;
        options.bPreferResidentKey = residentKey; // match bRequireResidentKey
    }
    // v5+: browser private mode
    if (optionsVersion >= 5) {
        options.bBrowserInPrivateMode = FALSE;
    }
    // v6+: enable PRF
    if (optionsVersion >= 6) {
        options.bEnablePrf = FALSE;
    }
    // v7+: linked device, JSON extensions
    // Left as zero (NULL) — no linked device, no JSON extensions

    // Print config
    std::cout << "  HWND:                 0x" << std::hex << (uintptr_t)hwnd << std::dec << std::endl;
    std::cout << "  Options version:      " << optionsVersion << std::endl;
    std::cout << "  bRequireResidentKey:  " << (residentKey ? "TRUE" : "FALSE") << std::endl;
    std::cout << "  bPreferResidentKey:   " << (residentKey ? "TRUE" : "FALSE") << std::endl;
    std::cout << "  Cancellation ID:      " << (hasCancellation ? "SET" : "NOT SET") << std::endl;
    std::cout << "  ExcludeCredentialList:" << (optionsVersion >= 3 ? " SET (empty)" : " NOT SET") << std::endl;
    std::cout << "  ClientData:           " << (useJsonClientData ? "JSON" : "raw bytes") << std::endl;
    std::cout << "  Timeout:              300s" << std::endl;
    std::cout << "  Attachment:           PLATFORM" << std::endl;
    std::cout << "  Calling WebAuthNAuthenticatorMakeCredential..." << std::endl;

    PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = nullptr;
    HRESULT hr = WebAuthNAuthenticatorMakeCredential(
        hwnd, &rpInfo, &userInfo, &pubKeyParams, &clientData, &options, &pAttestation
    );

    if (SUCCEEDED(hr)) {
        std::cout << "  => SUCCESS!" << std::endl;
        std::cout << "  Credential ID size:      " << pAttestation->cbCredentialId << " bytes" << std::endl;
        std::cout << "  AuthenticatorData size:  " << pAttestation->cbAuthenticatorData << " bytes" << std::endl;
        std::cout << "  Attestation format:      ";
        if (pAttestation->pwszFormatType) std::wcout << pAttestation->pwszFormatType;
        else std::cout << "(null)";
        std::cout << std::endl;
        std::cout << "  dwUsedTransport:         " << pAttestation->dwUsedTransport << std::endl;
        DWORD t = pAttestation->dwUsedTransport;
        if (t & WEBAUTHN_CTAP_TRANSPORT_USB)       std::cout << "    -> USB" << std::endl;
        if (t & WEBAUTHN_CTAP_TRANSPORT_NFC)       std::cout << "    -> NFC" << std::endl;
        if (t & WEBAUTHN_CTAP_TRANSPORT_BLE)       std::cout << "    -> BLE" << std::endl;
        if (t & WEBAUTHN_CTAP_TRANSPORT_INTERNAL)  std::cout << "    -> INTERNAL (platform)" << std::endl;

        std::ofstream outfile("test_credentialid.bin", std::ios::binary);
        outfile.write(reinterpret_cast<const char*>(pAttestation->pbCredentialId), pAttestation->cbCredentialId);
        outfile.close();
        std::cout << "  Saved credential to test_credentialid.bin" << std::endl;

        WebAuthNFreeCredentialAttestation(pAttestation);
        return true;
    } else {
        std::cout << "  => FAILED" << std::endl;
        print_hr("  ", hr);
        if (hr == (HRESULT)0x80090027) std::cerr << "  => NTE_INVALID_PARAMETER" << std::endl;
        if (hr == (HRESULT)0x800704C7) std::cerr << "  => ERROR_CANCELLED (user cancelled / internal failure)" << std::endl;
        if (hr == (HRESULT)0x80090020) std::cerr << "  => NTE_FAIL" << std::endl;
        if (hr == (HRESULT)0x80090029) std::cerr << "  => NTE_NOT_SUPPORTED" << std::endl;
        if (hr == (HRESULT)0x80004005) std::cerr << "  => E_FAIL" << std::endl;
        if (hr == (HRESULT)0x80070057) std::cerr << "  => E_INVALIDARG" << std::endl;
        return false;
    }
}

int main() {
    srand((unsigned)time(nullptr));
    std::cout << "=== WebAuthn Platform Credential Test Suite v4 ===" << std::endl;
    std::cout << "=== Testing browser-style options (cancellation ID, VERSION_7, JSON) ===" << std::endl;

    // --- Diagnostics ---
    print_separator("DIAGNOSTICS");
    DWORD apiVersion = WebAuthNGetApiVersionNumber();
    std::cout << "WebAuthN API version:       " << apiVersion << std::endl;
    std::cout << "SDK MAKE_CRED_OPTIONS max:  " << WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION << std::endl;

    BOOL platformAvail = FALSE;
    WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&platformAvail);
    std::cout << "Platform authenticator:     " << (platformAvail ? "AVAILABLE" : "NOT AVAILABLE") << std::endl;

    // Create hidden window for valid HWND
    std::cout << std::endl << "Creating hidden application window..." << std::endl;
    HWND hwnd = create_hidden_window();
    std::cout << "Hidden app HWND:            0x" << std::hex << (uintptr_t)hwnd << std::dec << std::endl;

    if (!hwnd) {
        std::cerr << "ERROR: Failed to create hidden window!" << std::endl;
        return 1;
    }

    // -------------------------------------------------------
    // TEST 1: Full browser-style — VERSION_7, cancellation ID, JSON clientData, residentKey=FALSE
    //   This is closest to what Firefox does
    // -------------------------------------------------------
    if (try_browser_style(hwnd,
            "TEST 1: Browser-style V7 + cancelId + JSON + non-resident",
            7, true, true, FALSE)) {
        std::cout << "\n>>> Browser-style options fix PLATFORM!" << std::endl;
        destroy_hidden_window();
        return 0;
    }

    // -------------------------------------------------------
    // TEST 2: VERSION_7, cancellation ID, JSON clientData, residentKey=TRUE
    // -------------------------------------------------------
    if (try_browser_style(hwnd,
            "TEST 2: Browser-style V7 + cancelId + JSON + resident",
            7, true, true, TRUE)) {
        std::cout << "\n>>> Works with residentKey=TRUE!" << std::endl;
        destroy_hidden_window();
        return 0;
    }

    // -------------------------------------------------------
    // TEST 3: VERSION_7, cancellation ID, raw clientData, residentKey=FALSE
    //   Tests if JSON clientData matters
    // -------------------------------------------------------
    if (try_browser_style(hwnd,
            "TEST 3: V7 + cancelId + raw challenge + non-resident",
            7, true, false, FALSE)) {
        std::cout << "\n>>> JSON clientData is NOT required!" << std::endl;
        destroy_hidden_window();
        return 0;
    }

    // -------------------------------------------------------
    // TEST 4: VERSION_7, NO cancellation ID, JSON clientData, residentKey=FALSE
    //   Tests if cancellation ID matters
    // -------------------------------------------------------
    if (try_browser_style(hwnd,
            "TEST 4: V7 + NO cancelId + JSON + non-resident",
            7, false, true, FALSE)) {
        std::cout << "\n>>> Cancellation ID is NOT required!" << std::endl;
        destroy_hidden_window();
        return 0;
    }

    // -------------------------------------------------------
    // TEST 5: VERSION_4 (simpler), cancellation ID, JSON, residentKey=FALSE
    //   Tests if the higher version fields matter
    // -------------------------------------------------------
    if (try_browser_style(hwnd,
            "TEST 5: V4 + cancelId + JSON + non-resident",
            4, true, true, FALSE)) {
        std::cout << "\n>>> VERSION_4 with cancelId+JSON works!" << std::endl;
        destroy_hidden_window();
        return 0;
    }

    std::cerr << std::endl << "All tests failed. Browser-style options do not help." << std::endl;
    destroy_hidden_window();
    return 1;
}
