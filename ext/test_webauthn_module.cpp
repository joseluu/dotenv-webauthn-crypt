#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <windows.h>
#include <webauthn.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

namespace py = pybind11;

std::wstring to_wstring(const std::string& s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    std::wstring ws(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &ws[0], len);
    return ws;
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

py::dict get_diagnostics() {
    py::dict d;
    d["api_version"] = (int)WebAuthNGetApiVersionNumber();
    BOOL avail = FALSE;
    WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&avail);
    d["platform_available"] = (bool)avail;
    d["sdk_make_cred_version"] = (int)WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
    d["sdk_get_assertion_version"] = (int)WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;

    // HWND info
    HWND fg = GetForegroundWindow();
    HWND console = GetConsoleWindow();
    d["foreground_hwnd"] = (uintptr_t)fg;
    d["console_hwnd"] = (uintptr_t)console;

    return d;
}

py::dict test_make_credential(const std::string& rp_id, int attachment) {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) hwnd = GetConsoleWindow();

    std::wstring wrp_id = to_wstring(rp_id);

    WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = { 0 };
    rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpInfo.pwszId = wrp_id.c_str();
    rpInfo.pwszName = L"Test Platform Auth";

    // Fresh user ID based on tick count
    DWORD tick = GetTickCount();
    BYTE userId[16];
    memset(userId, 0, 16);
    memcpy(userId, &tick, sizeof(tick));
    userId[4] = 0xDE; userId[5] = 0xAD;

    WEBAUTHN_USER_ENTITY_INFORMATION userInfo = { 0 };
    userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
    userInfo.cbId = 16;
    userInfo.pbId = userId;
    userInfo.pwszName = L"test_user";
    userInfo.pwszDisplayName = L"Test User";

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
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 120000;
    options.dwAuthenticatorAttachment = (DWORD)attachment;
    options.bRequireResidentKey = FALSE;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;

    py::dict result;
    result["hwnd"] = (uintptr_t)hwnd;
    result["attachment"] = attachment;
    result["rp_id"] = rp_id;

    PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = nullptr;
    HRESULT hr = WebAuthNAuthenticatorMakeCredential(
        hwnd, &rpInfo, &userInfo, &pubKeyParams, &clientData, &options, &pAttestation
    );

    result["hresult"] = (long)hr;
    result["hresult_str"] = hresult_str(hr);
    result["success"] = SUCCEEDED(hr);

    if (SUCCEEDED(hr)) {
        result["credential_id_size"] = (int)pAttestation->cbCredentialId;
        result["authenticator_data_size"] = (int)pAttestation->cbAuthenticatorData;
        result["used_transport"] = (int)pAttestation->dwUsedTransport;

        std::string transport_desc;
        DWORD t = pAttestation->dwUsedTransport;
        if (t & WEBAUTHN_CTAP_TRANSPORT_USB) transport_desc += "USB ";
        if (t & WEBAUTHN_CTAP_TRANSPORT_NFC) transport_desc += "NFC ";
        if (t & WEBAUTHN_CTAP_TRANSPORT_BLE) transport_desc += "BLE ";
        if (t & WEBAUTHN_CTAP_TRANSPORT_INTERNAL) transport_desc += "INTERNAL ";
        result["transport_desc"] = transport_desc;

        std::vector<uint8_t> cred_id(pAttestation->pbCredentialId,
            pAttestation->pbCredentialId + pAttestation->cbCredentialId);
        result["credential_id"] = cred_id;

        WebAuthNFreeCredentialAttestation(pAttestation);
    }

    return result;
}

PYBIND11_MODULE(_test_webauthn, m) {
    m.doc() = "Test module for WebAuthn platform authenticator hypothesis";
    m.def("get_diagnostics", &get_diagnostics, "Get WebAuthn API diagnostics");
    m.def("test_make_credential", &test_make_credential,
          "Test MakeCredential with specified attachment",
          py::arg("rp_id"), py::arg("attachment"));

    // Export attachment constants
    m.attr("ATTACHMENT_ANY") = (int)WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
    m.attr("ATTACHMENT_PLATFORM") = (int)WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
    m.attr("ATTACHMENT_CROSS_PLATFORM") = (int)WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
}
