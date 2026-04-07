/**
 * test_cross_platform.cpp
 *
 * Diagnostic test for cross-platform (phone/security key) passkey creation.
 * Designed to help troubleshoot failures when using an external device
 * (Android/iPhone via QR/hybrid, or USB security key) in environments where
 * corporate firewalls or Bluetooth policies may block communication.
 *
 * Runs 3 tests with increasing specificity:
 *   Test 1: CROSS_PLATFORM attachment, no hints   (shows full chooser)
 *   Test 2: CROSS_PLATFORM + hint "hybrid"         (forces QR/phone flow)
 *   Test 3: CROSS_PLATFORM + hint "security-key"   (forces USB key flow)
 *
 * Each test reports:
 *   - Raw HRESULT + WebAuthn error name + W3C DOM error mapping
 *   - Elapsed wall-clock time (helps distinguish timeout vs fast rejection)
 *   - Transport used / transports supported (when successful)
 *   - AAGUID + credential details (when successful)
 *
 * Common failure HRESULTs to look for:
 *   0x800704C7  ERROR_CANCELLED      — user dismissed the dialog
 *   0x80090027  NTE_INVALID_PARAMETER — bad options
 *   0x80090029  NTE_NOT_SUPPORTED    — authenticator does not support request
 *   0x80090011  NTE_NOT_FOUND        — no suitable authenticator found
 *   0x80090035  NTE_DEVICE_NOT_FOUND — device unreachable (BLE/hybrid blocked?)
 *   0x800705B4  ERROR_TIMEOUT        — operation timed out (firewall blocking tunnel?)
 *   0x80090030  NTE_DEVICE_NOT_READY — device present but not ready
 *   0x80090020  NTE_USER_CANCELLED   — user explicitly cancelled
 *
 * Build:  cd ext && bash build_tests.sh cross_platform
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "webauthn_v9.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <cstring>
#include <thread>
#include <atomic>
#include <chrono>

#pragma comment(lib, "webauthn.lib")
#pragma comment(lib, "user32.lib")

// ---------------------------------------------------------------------------
// Hidden window (needed for WebAuthn dialog)
// ---------------------------------------------------------------------------
static const wchar_t* HIDDEN_WND_CLASS = L"CrossPlatformTestWindow";
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
    HWND hwnd = CreateWindowExW(WS_EX_APPWINDOW, HIDDEN_WND_CLASS, L"CrossPlatform Helper",
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

void print_transport_flags(const char* label, DWORD transport) {
    std::cout << label << "0x" << std::hex << std::setw(4) << std::setfill('0')
              << transport << std::dec;
    if (transport == 0) { std::cout << " (none)" << std::endl; return; }
    std::cout << " =";
    if (transport & WEBAUTHN_CTAP_TRANSPORT_USB)       std::cout << " USB";
    if (transport & WEBAUTHN_CTAP_TRANSPORT_NFC)       std::cout << " NFC";
    if (transport & WEBAUTHN_CTAP_TRANSPORT_BLE)       std::cout << " BLE";
    if (transport & WEBAUTHN_CTAP_TRANSPORT_INTERNAL)  std::cout << " INTERNAL";
    if (transport & WEBAUTHN_CTAP_TRANSPORT_HYBRID)    std::cout << " HYBRID";
    if (transport & WEBAUTHN_CTAP_TRANSPORT_SMART_CARD) std::cout << " SMART_CARD";
    std::cout << std::endl;
}

void print_hresult_detail(HRESULT hr) {
    std::cout << "  HRESULT:                 0x" << std::hex << std::setw(8)
              << std::setfill('0') << (unsigned long)hr << std::dec << std::endl;

    // WebAuthn error name
    PCWSTR errName = WebAuthNGetErrorName(hr);
    if (errName) {
        char buf[256];
        WideCharToMultiByte(CP_UTF8, 0, errName, -1, buf, sizeof(buf), NULL, NULL);
        std::cout << "  WebAuthn error name:     " << buf << std::endl;
    }

    // W3C DOM error
    HRESULT domErr = WebAuthNGetW3CExceptionDOMError(hr);
    std::cout << "  W3C DOM error:           0x" << std::hex << std::setw(8)
              << std::setfill('0') << (unsigned long)domErr << std::dec << std::endl;

    // Human-readable diagnosis
    std::cout << "  Diagnosis:               ";
    switch ((unsigned long)hr) {
        case 0x00000000: std::cout << "S_OK — success"; break;
        case 0x800704C7: std::cout << "ERROR_CANCELLED — user closed the dialog"; break;
        case 0x800705B4: std::cout << "ERROR_TIMEOUT — timed out (firewall blocking tunnel server?)"; break;
        case 0x80090011: std::cout << "NTE_NOT_FOUND — no matching authenticator found"; break;
        case 0x80090020: std::cout << "NTE_USER_CANCELLED — user explicitly refused"; break;
        case 0x80090027: std::cout << "NTE_INVALID_PARAMETER — bad request parameters"; break;
        case 0x80090029: std::cout << "NTE_NOT_SUPPORTED — operation not supported by authenticator"; break;
        case 0x80090030: std::cout << "NTE_DEVICE_NOT_READY — device present but not ready"; break;
        case 0x80090035: std::cout << "NTE_DEVICE_NOT_FOUND — device unreachable (BLE/network blocked?)"; break;
        case 0x8009002D: std::cout << "NTE_EXISTS — credential already exists (InvalidStateError)"; break;
        case 0x80090023: std::cout << "NTE_TOKEN_KEYSET_STORAGE_FULL — authenticator storage full"; break;
        default:
            std::cout << "Unknown/other — check HRESULT";
            break;
    }
    std::cout << std::endl;
}

void parse_authenticator_data(const BYTE* authData, DWORD authDataLen) {
    if (authDataLen < 37) {
        std::cout << "  AuthData too short (" << authDataLen << " bytes)" << std::endl;
        return;
    }
    BYTE flags = authData[32];
    std::cout << "  AuthData flags:          0x" << std::hex << (int)flags << std::dec << std::endl;
    std::cout << "    UP (user present):     " << ((flags & 0x01) ? "YES" : "NO") << std::endl;
    std::cout << "    UV (user verified):    " << ((flags & 0x04) ? "YES" : "NO") << std::endl;
    std::cout << "    AT (attested cred):    " << ((flags & 0x40) ? "YES" : "NO") << std::endl;
    std::cout << "    ED (extensions):       " << ((flags & 0x80) ? "YES" : "NO") << std::endl;

    DWORD counter = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36];
    std::cout << "  Sign counter:            " << counter << std::endl;

    if ((flags & 0x40) && authDataLen >= 55) {
        print_guid_from_bytes("  AAGUID:                  ", authData + 37);
        bool allZero = true;
        for (int i = 0; i < 16; i++) if (authData[37 + i] != 0) { allZero = false; break; }
        if (allZero)
            std::cout << "  AAGUID note:             ALL ZEROS (anonymization/privacy mode)" << std::endl;
    }
}

// ---------------------------------------------------------------------------
// Enumerate authenticators (API v9) — pre-flight check
// ---------------------------------------------------------------------------
void list_authenticators() {
    std::cout << "========== PRE-FLIGHT: ENUMERATE AUTHENTICATORS ==========" << std::endl;

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
        std::cerr << "  GetAuthenticatorList failed: 0x"
                  << std::hex << (unsigned long)hr << std::dec << std::endl;
        FreeLibrary(hMod);
        return;
    }

    if (!pList || pList->cAuthenticatorDetails == 0) {
        std::cout << "  No authenticators found." << std::endl;
        std::cout << "  NOTE: This lists *currently connected* authenticators." << std::endl;
        std::cout << "        Phones appear only during active hybrid/BLE sessions." << std::endl;
    } else {
        std::cout << "  Found " << pList->cAuthenticatorDetails << " authenticator(s):" << std::endl;
        for (DWORD i = 0; i < pList->cAuthenticatorDetails; i++) {
            PWEBAUTHN_AUTHENTICATOR_DETAILS det = pList->ppAuthenticatorDetails[i];
            std::cout << std::endl;
            std::cout << "  [" << i << "] Name: ";
            if (det->pwszAuthenticatorName) std::wcout << det->pwszAuthenticatorName;
            else std::cout << "(null)";
            std::cout << std::endl;
            std::cout << "      ID size: " << det->cbAuthenticatorId << " bytes" << std::endl;
            std::cout << "      Locked:  " << (det->bLocked ? "YES" : "NO") << std::endl;
        }
    }

    pfnFree(pList);
    FreeLibrary(hMod);
}

// ---------------------------------------------------------------------------
// MakeCredential test — parameterized by hint
// ---------------------------------------------------------------------------
struct TestConfig {
    const char* testName;
    DWORD attachment;        // WEBAUTHN_AUTHENTICATOR_ATTACHMENT_*
    const wchar_t* hint;     // nullptr = no hint, or WEBAUTHN_CREDENTIAL_HINT_*
    DWORD timeoutMs;
};

void run_make_credential_test(HWND hwnd, const TestConfig& cfg) {
    std::cout << std::endl;
    std::cout << "========== " << cfg.testName << " ==========" << std::endl;
    std::cout << "  Attachment:              "
              << (cfg.attachment == WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM ? "CROSS_PLATFORM" :
                  cfg.attachment == WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM ? "PLATFORM" : "ANY")
              << std::endl;
    if (cfg.hint) {
        char hintUtf8[128];
        WideCharToMultiByte(CP_UTF8, 0, cfg.hint, -1, hintUtf8, sizeof(hintUtf8), NULL, NULL);
        std::cout << "  Hint:                    " << hintUtf8 << std::endl;
    } else {
        std::cout << "  Hint:                    (none)" << std::endl;
    }
    std::cout << "  Timeout:                 " << cfg.timeoutMs / 1000 << "s" << std::endl;

    // RP
    WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = { 0 };
    rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpInfo.pwszId = L"cross-platform-test.local";
    rpInfo.pwszName = L"Cross-Platform Diagnostic";

    // User (unique per test)
    time_t now = time(nullptr);
    BYTE userId[16] = { 0 };
    memcpy(userId, &now, sizeof(now));
    userId[8] = (BYTE)(rand() & 0xFF);
    userId[9] = (BYTE)(cfg.attachment & 0xFF);

    WEBAUTHN_USER_ENTITY_INFORMATION userInfo = { 0 };
    userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
    userInfo.cbId = 16;
    userInfo.pbId = userId;
    userInfo.pwszName = L"xplat_diag_user";
    userInfo.pwszDisplayName = L"Cross-Platform Diag User";

    // Algorithm
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER alg = { 0 };
    alg.dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
    alg.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    alg.lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pubKeyParams = { 1, &alg };

    // Challenge
    BYTE challenge[32];
    memset(challenge, 0xCC, 32);
    WEBAUTHN_CLIENT_DATA clientData = { 0 };
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = 32;
    clientData.pbClientDataJSON = challenge;
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    // Options
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options = { 0 };
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = cfg.timeoutMs;
    options.dwAuthenticatorAttachment = cfg.attachment;
    options.bRequireResidentKey = FALSE;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT;
    options.dwFlags = 0;

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

    // v6
    options.bEnablePrf = FALSE;

    // v7
    options.pLinkedDevice = nullptr;
    options.cbJsonExt = 0;
    options.pbJsonExt = nullptr;

    // v8: hints
    LPCWSTR hintArray[1];
    options.pPRFGlobalEval = nullptr;
    if (cfg.hint) {
        hintArray[0] = cfg.hint;
        options.cCredentialHints = 1;
        options.ppwszCredentialHints = hintArray;
    } else {
        options.cCredentialHints = 0;
        options.ppwszCredentialHints = nullptr;
    }
    options.bThirdPartyPayment = FALSE;

    // v9
    options.pwszRemoteWebOrigin = nullptr;
    options.cbPublicKeyCredentialCreationOptionsJSON = 0;
    options.pbPublicKeyCredentialCreationOptionsJSON = nullptr;
    options.cbAuthenticatorId = 0;
    options.pbAuthenticatorId = nullptr;

    std::cout << std::endl;
    std::cout << "  Calling MakeCredential..." << std::endl;
    std::cout << "  >> Use your EXTERNAL device (phone/security key) when prompted <<" << std::endl;
    std::cout << std::endl;

    auto t_start = std::chrono::steady_clock::now();

    PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = nullptr;
    HRESULT hr = WebAuthNAuthenticatorMakeCredential(
        hwnd, &rpInfo, &userInfo, &pubKeyParams, &clientData, &options, &pAttestation
    );

    auto t_end = std::chrono::steady_clock::now();
    double elapsed_sec = std::chrono::duration<double>(t_end - t_start).count();

    std::cout << "  --- Result ---" << std::endl;
    std::cout << "  Elapsed time:            " << std::fixed << std::setprecision(1) << elapsed_sec << "s" << std::endl;

    if (FAILED(hr)) {
        print_hresult_detail(hr);

        // Transport-specific failure hints
        std::cout << std::endl;
        std::cout << "  --- Troubleshooting ---" << std::endl;
        if ((unsigned long)hr == 0x800705B4) {
            std::cout << "  * TIMEOUT: The operation ran for the full timeout period." << std::endl;
            std::cout << "    This often means the hybrid/caBLE tunnel server was unreachable." << std::endl;
            std::cout << "    Check: Is cable.ua5v.com / cable.auth.com reachable?" << std::endl;
            std::cout << "    Check: Corporate firewall/proxy blocking WebSocket connections?" << std::endl;
            std::cout << "    Check: Both devices on networks that allow outbound HTTPS?" << std::endl;
        } else if ((unsigned long)hr == 0x80090035) {
            std::cout << "  * DEVICE_NOT_FOUND: The authenticator could not be reached." << std::endl;
            std::cout << "    Check: Is Bluetooth enabled and working on this PC?" << std::endl;
            std::cout << "    Check: Is Bluetooth restricted to audio-only by policy?" << std::endl;
            std::cout << "    Check: Is the phone nearby with Bluetooth/WiFi enabled?" << std::endl;
            std::cout << "    Try:   Settings > Bluetooth > make sure it's ON" << std::endl;
        } else if ((unsigned long)hr == 0x800704C7 || (unsigned long)hr == 0x80090020) {
            std::cout << "  * User cancelled or dialog was dismissed." << std::endl;
            if (elapsed_sec < 5.0) {
                std::cout << "    NOTE: Very fast cancellation (" << std::fixed << std::setprecision(1)
                          << elapsed_sec << "s) may indicate the OS could not" << std::endl;
                std::cout << "    even present the external device option." << std::endl;
            }
        } else if ((unsigned long)hr == 0x80090011) {
            std::cout << "  * NOT_FOUND: No authenticator matching the request was found." << std::endl;
            std::cout << "    If you tried to use a phone: the hybrid transport may be" << std::endl;
            std::cout << "    blocked or the QR code could not establish a connection." << std::endl;
        } else if ((unsigned long)hr == 0x80090029) {
            std::cout << "  * NOT_SUPPORTED: The authenticator does not support this operation." << std::endl;
            std::cout << "    The external device may not support the requested options." << std::endl;
        }

        if (cfg.hint && wcscmp(cfg.hint, WEBAUTHN_CREDENTIAL_HINT_HYBRID) == 0) {
            std::cout << std::endl;
            std::cout << "  --- Hybrid (caBLE) specific checks ---" << std::endl;
            std::cout << "  The hybrid flow requires:" << std::endl;
            std::cout << "    1. Bluetooth LE on this PC (not just classic BT)" << std::endl;
            std::cout << "    2. BLE not restricted by Group Policy / MDM" << std::endl;
            std::cout << "    3. Outbound HTTPS to caBLE tunnel relay servers" << std::endl;
            std::cout << "    4. Phone: Bluetooth + WiFi/cellular data enabled" << std::endl;
            std::cout << "    5. Phone: screen unlocked when scanning QR" << std::endl;
        }

        return;
    }

    // --- SUCCESS ---
    std::cout << "  Result:                  SUCCESS" << std::endl;
    print_hresult_detail(hr);
    std::cout << std::endl;

    std::cout << "  --- Attestation details ---" << std::endl;
    std::cout << "  Attestation version:     " << pAttestation->dwVersion << std::endl;
    std::cout << "  Format type:             ";
    if (pAttestation->pwszFormatType) std::wcout << pAttestation->pwszFormatType;
    else std::cout << "(null)";
    std::cout << std::endl;

    std::cout << "  Credential ID size:      " << pAttestation->cbCredentialId << " bytes" << std::endl;
    print_hex("  Credential ID:           ", pAttestation->pbCredentialId,
              pAttestation->cbCredentialId > 64 ? 64 : pAttestation->cbCredentialId);
    if (pAttestation->cbCredentialId > 64)
        std::cout << "    (truncated, total " << pAttestation->cbCredentialId << " bytes)" << std::endl;

    // Transport used (v3+)
    if (pAttestation->dwVersion >= 3) {
        print_transport_flags("  Used transport:          ", pAttestation->dwUsedTransport);
    }

    // Supported transports (v8+)
    if (pAttestation->dwVersion >= 8) {
        print_transport_flags("  Supported transports:    ", pAttestation->dwTransports);
    }

    // v4 fields
    if (pAttestation->dwVersion >= 4) {
        std::cout << "  bResidentKey:            " << (pAttestation->bResidentKey ? "TRUE" : "FALSE") << std::endl;
        std::cout << "  bLargeBlobSupported:     " << (pAttestation->bLargeBlobSupported ? "TRUE" : "FALSE") << std::endl;
    }

    // v5 PRF
    if (pAttestation->dwVersion >= 5) {
        std::cout << "  bPrfEnabled:             " << (pAttestation->bPrfEnabled ? "TRUE" : "FALSE") << std::endl;
    }

    // Extensions
    std::cout << "  Extension count:         " << pAttestation->Extensions.cExtensions << std::endl;
    for (DWORD i = 0; i < pAttestation->Extensions.cExtensions; i++) {
        PWEBAUTHN_EXTENSION ext = &pAttestation->Extensions.pExtensions[i];
        char extName[256];
        WideCharToMultiByte(CP_UTF8, 0, ext->pwszExtensionIdentifier, -1, extName, sizeof(extName), NULL, NULL);
        std::cout << "    [" << i << "] " << extName << " (size=" << ext->cbExtension << ")" << std::endl;
    }

    // AuthenticatorData — AAGUID
    std::cout << std::endl << "  --- AuthenticatorData ---" << std::endl;
    parse_authenticator_data(pAttestation->pbAuthenticatorData, pAttestation->cbAuthenticatorData);

    WebAuthNFreeCredentialAttestation(pAttestation);
}

// ---------------------------------------------------------------------------
// BLE adapter check (best-effort via SetupAPI)
// ---------------------------------------------------------------------------
void check_bluetooth_status() {
    std::cout << "========== PRE-FLIGHT: BLUETOOTH CHECK ==========" << std::endl;

    // Try to find Bluetooth radios via the Bluetooth API
    typedef HANDLE (WINAPI *PFN_FindFirstRadio)(void*, HANDLE*);
    typedef BOOL (WINAPI *PFN_FindNextRadio)(HANDLE, HANDLE*);
    typedef BOOL (WINAPI *PFN_FindRadioClose)(HANDLE);
    typedef DWORD (WINAPI *PFN_GetRadioInfo)(HANDLE, void*);

    HMODULE hBthProps = LoadLibraryW(L"bthprops.cpl");
    if (!hBthProps) {
        std::cout << "  Could not load bthprops.cpl — Bluetooth stack may not be installed." << std::endl;
        std::cout << "  HYBRID/caBLE transport will NOT work without Bluetooth." << std::endl;
        return;
    }

    auto pfnFindFirst = (PFN_FindFirstRadio)GetProcAddress(hBthProps, "BluetoothFindFirstRadio");
    auto pfnFindNext = (PFN_FindNextRadio)GetProcAddress(hBthProps, "BluetoothFindNextRadio");
    auto pfnFindClose = (PFN_FindRadioClose)GetProcAddress(hBthProps, "BluetoothFindRadioClose");

    if (!pfnFindFirst || !pfnFindNext || !pfnFindClose) {
        std::cout << "  Bluetooth API functions not found." << std::endl;
        FreeLibrary(hBthProps);
        return;
    }

    // BLUETOOTH_FIND_RADIO_PARAMS
    struct { DWORD dwSize; } findParams = { sizeof(findParams) };
    HANDLE hRadio = nullptr;
    HANDLE hFind = pfnFindFirst(&findParams, &hRadio);

    if (hFind == nullptr || hFind == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        std::cout << "  No Bluetooth radio found (error " << err << ")." << std::endl;
        if (err == 259 /* ERROR_NO_MORE_ITEMS */) {
            std::cout << "  => No BT adapter detected. Hybrid/caBLE will fail." << std::endl;
            std::cout << "  => USB security keys will still work." << std::endl;
        }
    } else {
        int radioCount = 0;
        do {
            radioCount++;
            if (hRadio) CloseHandle(hRadio);
        } while (pfnFindNext(hFind, &hRadio));
        pfnFindClose(hFind);
        std::cout << "  Found " << radioCount << " Bluetooth radio(s) — BT hardware present." << std::endl;
        std::cout << "  NOTE: BLE may still be restricted by Group Policy/MDM." << std::endl;
        std::cout << "        If hybrid fails, check 'Allow Bluetooth' and" << std::endl;
        std::cout << "        'Bluetooth Allowed Services' in Group Policy." << std::endl;
    }

    FreeLibrary(hBthProps);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main() {
    srand((unsigned)time(nullptr));
    std::cout << "================================================================" << std::endl;
    std::cout << "  Cross-Platform / External Device Passkey Diagnostic" << std::endl;
    std::cout << "================================================================" << std::endl;
    std::cout << std::endl;

    DWORD apiVersion = WebAuthNGetApiVersionNumber();
    std::cout << "WebAuthN API version:      " << apiVersion << std::endl;

    BOOL platformAvail = FALSE;
    WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&platformAvail);
    std::cout << "Platform authenticator:    " << (platformAvail ? "YES" : "NO") << std::endl;

    std::cout << "SDK options version:       " << WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION << std::endl;
    std::cout << "Hint support:              " << (apiVersion >= 8 ? "YES (API >= 8)" : "NO (API < 8, hints ignored)") << std::endl;
    std::cout << std::endl;

    // Pre-flight checks
    check_bluetooth_status();
    std::cout << std::endl;
    list_authenticators();

    HWND hwnd = create_hidden_window();
    if (!hwnd) {
        std::cerr << "ERROR: Failed to create window" << std::endl;
        return 1;
    }
    std::cout << std::endl << "Using hidden app HWND:     0x" << std::hex << (uintptr_t)hwnd << std::dec << std::endl;

    // -----------------------------------------------------------------------
    // Test menu
    // -----------------------------------------------------------------------
    std::cout << std::endl;
    std::cout << "================================================================" << std::endl;
    std::cout << "  Select test to run:" << std::endl;
    std::cout << "    1 = Cross-platform, no hint (shows full external chooser)" << std::endl;
    std::cout << "    2 = Cross-platform + hybrid hint (forces QR/phone flow)" << std::endl;
    std::cout << "    3 = Cross-platform + security-key hint (forces USB key)" << std::endl;
    std::cout << "    a = Run all 3 tests sequentially" << std::endl;
    std::cout << "    q = Quit" << std::endl;
    std::cout << "================================================================" << std::endl;

    TestConfig tests[] = {
        { "TEST 1: CROSS_PLATFORM, no hint",
          WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM, nullptr, 120000 },
        { "TEST 2: CROSS_PLATFORM + hint=hybrid (QR/phone)",
          WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM, WEBAUTHN_CREDENTIAL_HINT_HYBRID, 120000 },
        { "TEST 3: CROSS_PLATFORM + hint=security-key (USB)",
          WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM, WEBAUTHN_CREDENTIAL_HINT_SECURITY_KEY, 60000 },
    };

    while (true) {
        std::cout << std::endl << "  Choice [1/2/3/a/q]: ";
        char choice;
        std::cin >> choice;

        if (choice == 'q' || choice == 'Q') break;

        if (choice == '1') {
            run_make_credential_test(hwnd, tests[0]);
        } else if (choice == '2') {
            run_make_credential_test(hwnd, tests[1]);
        } else if (choice == '3') {
            run_make_credential_test(hwnd, tests[2]);
        } else if (choice == 'a' || choice == 'A') {
            for (int i = 0; i < 3; i++) {
                run_make_credential_test(hwnd, tests[i]);
                if (i < 2) {
                    std::cout << std::endl << "  Press Enter for next test...";
                    std::cin.ignore();
                    std::cin.get();
                }
            }
        } else {
            std::cout << "  Invalid choice." << std::endl;
        }
    }

    destroy_hidden_window();
    std::cout << std::endl;
    std::cout << "================================================================" << std::endl;
    std::cout << "  Troubleshooting reference:" << std::endl;
    std::cout << "    0x800704C7 = ERROR_CANCELLED       (user dismissed)" << std::endl;
    std::cout << "    0x800705B4 = ERROR_TIMEOUT          (tunnel unreachable?)" << std::endl;
    std::cout << "    0x80090011 = NTE_NOT_FOUND          (no authenticator)" << std::endl;
    std::cout << "    0x80090020 = NTE_USER_CANCELLED     (user refused)" << std::endl;
    std::cout << "    0x80090027 = NTE_INVALID_PARAMETER  (bad request)" << std::endl;
    std::cout << "    0x80090029 = NTE_NOT_SUPPORTED      (unsupported)" << std::endl;
    std::cout << "    0x80090035 = NTE_DEVICE_NOT_FOUND   (BLE/device blocked?)" << std::endl;
    std::cout << "================================================================" << std::endl;
    return 0;
}
