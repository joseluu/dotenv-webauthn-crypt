#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include "webauthn_v9.h"
#include <keycredmgr.h>
#include <bluetoothapis.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <atomic>
#include <thread>

// The version is injected at build time by setup.py
#ifndef PROJECT_VERSION
#define PROJECT_VERSION "0.3.0a6"
#endif

namespace py = pybind11;

// ---------------------------------------------------------------------------
// Hidden application window — provides a proper HWND for the WebAuthn dialog
// The dialog shows different options depending on whether the HWND belongs to
// a real app window vs a console window.
// ---------------------------------------------------------------------------
static const wchar_t* HIDDEN_WND_CLASS = L"WebAuthnPybindWindow";
static std::atomic<HWND> g_hiddenHwnd{nullptr};
static std::atomic<bool> g_msgLoopReady{false};
static std::thread g_msgLoopThread;

static LRESULT CALLBACK HiddenWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void message_loop_func() {
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

static HWND get_app_hwnd() {
    if (!g_msgLoopReady.load()) {
        g_msgLoopThread = std::thread(message_loop_func);
        g_msgLoopThread.detach();
        while (!g_msgLoopReady.load()) Sleep(10);
    }
    return g_hiddenHwnd.load();
}

// Helper to convert std::string to std::wstring
std::wstring to_wstring(const std::string& s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    std::wstring ws(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &ws[0], len);
    return ws;
}

// hint: "client-device" = Windows Hello, "hybrid" = phone/QR, "security-key" = USB, "" = chooser
py::dict make_credential(const std::string& rp_id, const std::string& user_name, const std::string& hint) {
    HWND hwnd = get_app_hwnd();
    std::wstring wrp_id = to_wstring(rp_id);
    std::wstring wuser_name = to_wstring(user_name);

    WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = { 0 };
    rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpInfo.pwszId = wrp_id.c_str();
    rpInfo.pwszName = L"Dotenv WebAuthn Crypt";

    // Use the user_name as the user ID (UTF-8 bytes)
    WEBAUTHN_USER_ENTITY_INFORMATION userInfo = { 0 };
    userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
    userInfo.cbId = (DWORD)user_name.size();
    userInfo.pbId = (PBYTE)user_name.c_str();
    userInfo.pwszName = wuser_name.c_str();
    userInfo.pwszDisplayName = wuser_name.c_str();

    WEBAUTHN_COSE_CREDENTIAL_PARAMETER alg = { 0 };
    alg.dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
    alg.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    alg.lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pubKeyParams = { 1, &alg };

    BYTE challenge[32];
    memset(challenge, 0xEE, 32);
    WEBAUTHN_CLIENT_DATA clientData = { 0 };
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = 32;
    clientData.pbClientDataJSON = challenge;
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options = { 0 };
    options.dwVersion = 9;  // v9 for credential hints + authenticator targeting
    options.dwTimeoutMilliseconds = 120000;
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

    // v8: credential hints
    options.pPRFGlobalEval = nullptr;
    options.bThirdPartyPayment = FALSE;
    std::wstring whint;
    LPCWSTR hintPtr = nullptr;
    if (!hint.empty()) {
        whint = to_wstring(hint);
        hintPtr = whint.c_str();
        options.cCredentialHints = 1;
        options.ppwszCredentialHints = &hintPtr;
    } else {
        options.cCredentialHints = 0;
        options.ppwszCredentialHints = nullptr;
    }

    // v9: remote web origin, JSON options, authenticator ID
    options.pwszRemoteWebOrigin = nullptr;
    options.cbPublicKeyCredentialCreationOptionsJSON = 0;
    options.pbPublicKeyCredentialCreationOptionsJSON = nullptr;
    options.cbAuthenticatorId = 0;
    options.pbAuthenticatorId = nullptr;

    PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = nullptr;
    HRESULT hr = WebAuthNAuthenticatorMakeCredential(hwnd, &rpInfo, &userInfo, &pubKeyParams, &clientData, &options, &pAttestation);

    if (FAILED(hr)) {
        throw std::runtime_error("WebAuthNAuthenticatorMakeCredential failed with HRESULT: " + std::to_string(hr));
    }

    std::vector<uint8_t> cred_id(pAttestation->pbCredentialId,
                                  pAttestation->pbCredentialId + pAttestation->cbCredentialId);
    std::vector<uint8_t> auth_data(pAttestation->pbAuthenticatorData,
                                    pAttestation->pbAuthenticatorData + pAttestation->cbAuthenticatorData);

    // Extract transport info
    DWORD transport = pAttestation->dwUsedTransport;
    std::string transport_str;
    if (transport & WEBAUTHN_CTAP_TRANSPORT_INTERNAL)  transport_str = "internal";
    else if (transport & WEBAUTHN_CTAP_TRANSPORT_HYBRID) transport_str = "hybrid";
    else if (transport & WEBAUTHN_CTAP_TRANSPORT_USB)    transport_str = "usb";
    else if (transport & WEBAUTHN_CTAP_TRANSPORT_NFC)    transport_str = "nfc";
    else if (transport & WEBAUTHN_CTAP_TRANSPORT_BLE)    transport_str = "ble";
    else transport_str = "unknown";

    // Extract AAGUID from authenticator data (bytes 37-52, if AT flag set)
    std::string aaguid_str;
    if (auth_data.size() >= 53 && (auth_data[32] & 0x40)) {
        std::ostringstream oss;
        for (int i = 37; i < 53; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)auth_data[i];
            if (i == 40 || i == 42 || i == 44 || i == 46) oss << "-";
        }
        aaguid_str = oss.str();
    }

    WebAuthNFreeCredentialAttestation(pAttestation);

    py::dict result;
    result["credential_id"] = cred_id;
    result["authenticator_data"] = auth_data;
    result["transport"] = transport_str;
    result["aaguid"] = aaguid_str;
    return result;
}

py::dict get_assertion(const std::string& rp_id, const std::vector<uint8_t>& credential_id,
                       const std::vector<uint8_t>& challenge, const std::string& hint) {
    HWND hwnd = get_app_hwnd();
    std::wstring wrp_id = to_wstring(rp_id);

    WEBAUTHN_CLIENT_DATA clientData = { 0 };
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = (DWORD)challenge.size();
    clientData.pbClientDataJSON = (PBYTE)challenge.data();
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    WEBAUTHN_CREDENTIAL cred = { 0 };
    cred.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
    cred.cbId = (DWORD)credential_id.size();
    cred.pbId = const_cast<PBYTE>(credential_id.data());
    cred.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    WEBAUTHN_CREDENTIALS creds = { 1, &cred };

    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options = { 0 };
    options.dwVersion = 9;  // v9 for credential hints + authenticator targeting
    options.dwTimeoutMilliseconds = 120000;
    options.CredentialList = creds;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwFlags = 0;

    // v2: cancellation
    GUID cancellationId = { 0 };
    if (SUCCEEDED(WebAuthNGetCancellationId(&cancellationId))) {
        options.pCancellationId = &cancellationId;
    }

    // v3: allowlist (use v1 CredentialList above)
    options.pAllowCredentialList = nullptr;

    // v4: allow credential list (use v1 CredentialList instead)
    options.pAllowCredentialList = nullptr;

    // v5: large blob
    options.dwCredLargeBlobOperation = WEBAUTHN_CRED_LARGE_BLOB_OPERATION_NONE;
    options.cbCredLargeBlob = 0;
    options.pbCredLargeBlob = nullptr;

    // v6: PRF + browser private mode
    options.pHmacSecretSaltValues = nullptr;
    options.bBrowserInPrivateMode = FALSE;

    // v7: linked device, autofill, JSON ext
    options.pLinkedDevice = nullptr;
    options.bAutoFill = FALSE;
    options.cbJsonExt = 0;
    options.pbJsonExt = nullptr;

    // v8: credential hints
    std::wstring whint;
    LPCWSTR hintPtr = nullptr;
    if (!hint.empty()) {
        whint = to_wstring(hint);
        hintPtr = whint.c_str();
        options.cCredentialHints = 1;
        options.ppwszCredentialHints = &hintPtr;
    } else {
        options.cCredentialHints = 0;
        options.ppwszCredentialHints = nullptr;
    }

    // v9: remote web origin, JSON options, authenticator ID
    options.pwszRemoteWebOrigin = nullptr;
    options.cbPublicKeyCredentialRequestOptionsJSON = 0;
    options.pbPublicKeyCredentialRequestOptionsJSON = nullptr;
    options.cbAuthenticatorId = 0;
    options.pbAuthenticatorId = nullptr;

    PWEBAUTHN_ASSERTION pAssertion = nullptr;
    HRESULT hr = WebAuthNAuthenticatorGetAssertion(hwnd, wrp_id.c_str(), &clientData, &options, &pAssertion);

    if (FAILED(hr)) {
        throw std::runtime_error("WebAuthNAuthenticatorGetAssertion failed with HRESULT: " + std::to_string(hr));
    }

    std::vector<uint8_t> signature(pAssertion->pbSignature,
                                   pAssertion->pbSignature + pAssertion->cbSignature);
    std::vector<uint8_t> auth_data(pAssertion->pbAuthenticatorData,
                                   pAssertion->pbAuthenticatorData + pAssertion->cbAuthenticatorData);
    WebAuthNFreeAssertion(pAssertion);

    py::dict result;
    result["signature"] = signature;
    result["authenticator_data"] = auth_data;
    return result;
}

py::dict get_platform_status() {
    py::dict result;

    // 1. WebAuthn API version
    DWORD apiVersion = WebAuthNGetApiVersionNumber();
    result["api_version"] = (int)apiVersion;

    // 2. Platform authenticator hardware available
    BOOL platformAvail = FALSE;
    WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&platformAvail);
    result["platform_available"] = (bool)platformAvail;

    // 3. NGC provisioning status
    BOOL isReady = FALSE;
    KeyCredentialManagerOperationErrorStates errorStates = KeyCredentialManagerOperationErrorStateNone;
    HRESULT hr = KeyCredentialManagerGetOperationErrorStates(
        KeyCredentialManagerProvisioning, &isReady, &errorStates);

    result["ngc_ready"] = SUCCEEDED(hr) && (bool)isReady;
    result["ngc_error_flags"] = (int)errorStates;

    // Decode error flags into a list of strings
    py::list errors;
    if (errorStates & KeyCredentialManagerOperationErrorStateDeviceJoinFailure)
        errors.append("DeviceJoinFailure");
    if (errorStates & KeyCredentialManagerOperationErrorStateTokenFailure)
        errors.append("TokenFailure");
    if (errorStates & KeyCredentialManagerOperationErrorStateCertificateFailure)
        errors.append("CertificateFailure");
    if (errorStates & KeyCredentialManagerOperationErrorStateRemoteSessionFailure)
        errors.append("RemoteSessionFailure");
    if (errorStates & KeyCredentialManagerOperationErrorStatePolicyFailure)
        errors.append("PolicyFailure");
    if (errorStates & KeyCredentialManagerOperationErrorStateHardwareFailure)
        errors.append("HardwareFailure");
    if (errorStates & KeyCredentialManagerOperationErrorStatePinExistsFailure)
        errors.append("PinExistsFailure");
    result["ngc_errors"] = errors;

    // 4. Bluetooth availability (needed for hybrid/phone transport)
    BLUETOOTH_FIND_RADIO_PARAMS btParams = { sizeof(BLUETOOTH_FIND_RADIO_PARAMS) };
    HANDLE hRadio = NULL;
    HBLUETOOTH_RADIO_FIND hFind = BluetoothFindFirstRadio(&btParams, &hRadio);
    if (hFind) {
        result["bluetooth_available"] = true;
        CloseHandle(hRadio);
        BluetoothFindRadioClose(hFind);
    } else {
        result["bluetooth_available"] = false;
    }

    // 5. Network connectivity (needed for hybrid/phone transport)
    // Quick check: try to resolve a known host via WinHTTP (loaded dynamically)
    typedef void* HINTERNET_T;
    typedef HINTERNET_T (WINAPI *PFN_Open)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    typedef HINTERNET_T (WINAPI *PFN_Connect)(HINTERNET_T, LPCWSTR, WORD, DWORD);
    typedef BOOL (WINAPI *PFN_CloseHandle)(HINTERNET_T);
    HMODULE hWinHttp = LoadLibraryW(L"winhttp.dll");
    result["network_available"] = false;
    if (hWinHttp) {
        auto pfnOpen = (PFN_Open)GetProcAddress(hWinHttp, "WinHttpOpen");
        auto pfnConnect = (PFN_Connect)GetProcAddress(hWinHttp, "WinHttpConnect");
        auto pfnClose = (PFN_CloseHandle)GetProcAddress(hWinHttp, "WinHttpCloseHandle");
        if (pfnOpen && pfnConnect && pfnClose) {
            HINTERNET_T hSession = pfnOpen(L"dotenv-webauthn/check", 0, NULL, NULL, 0);
            if (hSession) {
                HINTERNET_T hConnect = pfnConnect(hSession, L"clients3.google.com", 443, 0);
                if (hConnect) {
                    result["network_available"] = true;
                    pfnClose(hConnect);
                }
                pfnClose(hSession);
            }
        }
        FreeLibrary(hWinHttp);
    }

    // 6. NGC container info
    KeyCredentialManagerInfo* info = nullptr;
    hr = KeyCredentialManagerGetInformation(&info);
    if (SUCCEEDED(hr) && info) {
        OLECHAR guidStr[40];
        StringFromGUID2(info->containerId, guidStr, 40);
        char buf[80];
        WideCharToMultiByte(CP_UTF8, 0, guidStr, -1, buf, sizeof(buf), NULL, NULL);
        result["ngc_container"] = std::string(buf);
        KeyCredentialManagerFreeInformation(info);
    } else {
        result["ngc_container"] = py::none();
    }

    return result;
}

std::string get_version() {
    return PROJECT_VERSION;
}

PYBIND11_MODULE(_webauthn, m) {
    m.def("get_version", &get_version, "Get native module version");
    m.def("make_credential", &make_credential,
          "Create a WebAuthn credential",
          py::arg("rp_id"), py::arg("user_name"), py::arg("hint") = "");
    m.def("get_assertion", &get_assertion,
          "Get WebAuthn assertion (signature)",
          py::arg("rp_id"), py::arg("credential_id"), py::arg("challenge"), py::arg("hint") = "");
    m.def("get_platform_status", &get_platform_status, "Get platform authenticator status");
}
