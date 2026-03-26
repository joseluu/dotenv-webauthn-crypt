#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <windows.h>
#include <webauthn.h>
#include <vector>
#include <string>
#include <stdexcept>

// The version is injected at build time by setup.py
#ifndef PROJECT_VERSION
#define PROJECT_VERSION "0.2.1"
#endif

namespace py = pybind11;

// Helper to convert std::string to std::wstring
std::wstring to_wstring(const std::string& s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    std::wstring ws(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &ws[0], len);
    return ws;
}

std::vector<uint8_t> make_credential(const std::string& rp_id, const std::string& user_name) {
    HWND hwnd = GetForegroundWindow();
    std::wstring wrp_id = to_wstring(rp_id);
    std::wstring wuser_name = to_wstring(user_name);

    WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = { 0 };
    rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpInfo.pwszId = wrp_id.c_str();
    rpInfo.pwszName = L"Dotenv WebAuthn Crypt";

    BYTE userId[] = "user123"; 
    WEBAUTHN_USER_ENTITY_INFORMATION userInfo = { 0 };
    userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
    userInfo.cbId = sizeof(userId);
    userInfo.pbId = userId;
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
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
    options.bRequireResidentKey = FALSE;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
    options.bEnablePrf = TRUE;

    PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = nullptr;
    HRESULT hr = WebAuthNAuthenticatorMakeCredential(hwnd, &rpInfo, &userInfo, &pubKeyParams, &clientData, &options, &pAttestation);

    if (FAILED(hr)) {
        throw std::runtime_error("WebAuthNAuthenticatorMakeCredential failed with HRESULT: " + std::to_string(hr));
    }

    std::vector<uint8_t> result(pAttestation->pbCredentialId, pAttestation->pbCredentialId + pAttestation->cbCredentialId);
    WebAuthNFreeCredentialAttestation(pAttestation);
    return result;
}

std::vector<uint8_t> get_assertion(const std::string& rp_id, const std::vector<uint8_t>& credential_id, const std::vector<uint8_t>& salt) {
    HWND hwnd = GetForegroundWindow();
    std::wstring wrp_id = to_wstring(rp_id);

    // Use the salt as client data (challenge)
    WEBAUTHN_CLIENT_DATA clientData = { 0 };
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = (DWORD)salt.size();
    clientData.pbClientDataJSON = (PBYTE)salt.data();
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    WEBAUTHN_CREDENTIAL cred = { 0 };
    cred.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
    cred.cbId = (DWORD)credential_id.size();
    cred.pbId = const_cast<PBYTE>(credential_id.data());
    cred.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    WEBAUTHN_CREDENTIALS creds = { 1, &cred };

    // Set up hmac-secret salt (must be 32 bytes)
    // Use WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG to pass raw salt
    WEBAUTHN_HMAC_SECRET_SALT hmacSalt = { 0 };
    hmacSalt.cbFirst = (DWORD)salt.size();
    hmacSalt.pbFirst = const_cast<PBYTE>(salt.data());
    hmacSalt.cbSecond = 0;
    hmacSalt.pbSecond = nullptr;

    WEBAUTHN_HMAC_SECRET_SALT_VALUES hmacSaltValues = { 0 };
    hmacSaltValues.pGlobalHmacSalt = &hmacSalt;
    hmacSaltValues.cCredWithHmacSecretSaltList = 0;
    hmacSaltValues.pCredWithHmacSecretSaltList = nullptr;

    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options = { 0 };
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000;
    options.CredentialList = creds;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwFlags = WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG;
    options.pHmacSecretSaltValues = &hmacSaltValues;

    PWEBAUTHN_ASSERTION pAssertion = nullptr;
    HRESULT hr = WebAuthNAuthenticatorGetAssertion(hwnd, wrp_id.c_str(), &clientData, &options, &pAssertion);

    if (FAILED(hr)) {
        throw std::runtime_error("WebAuthNAuthenticatorGetAssertion failed with HRESULT: " + std::to_string(hr));
    }

    // Return the deterministic HMAC secret, not the signature
    if (!pAssertion->pHmacSecret || !pAssertion->pHmacSecret->pbFirst || pAssertion->pHmacSecret->cbFirst == 0) {
        WebAuthNFreeAssertion(pAssertion);
        throw std::runtime_error("Authenticator did not return HMAC secret (PRF not supported by this authenticator)");
    }

    std::vector<uint8_t> result(pAssertion->pHmacSecret->pbFirst,
                                pAssertion->pHmacSecret->pbFirst + pAssertion->pHmacSecret->cbFirst);
    WebAuthNFreeAssertion(pAssertion);
    return result;
}

std::string get_version() {
    return PROJECT_VERSION;
}

PYBIND11_MODULE(_native, m) {
    m.def("get_version", &get_version, "Get native module version");
    m.def("make_credential", &make_credential, "Create a WebAuthn credential (non-resident)");
    m.def("get_assertion", &get_assertion, "Get WebAuthn assertion (signature)");
}
