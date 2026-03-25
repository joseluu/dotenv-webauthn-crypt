#include <windows.h>
#include <webauthn.h>
#include <iostream>
#include <fstream>
#include <string>

#pragma comment(lib, "webauthn.lib")

/**
 * REPRODUCER: This program demonstrates the "There was a problem saving your passkey" error
 * by forcing WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM and bRequireResidentKey = TRUE.
 */
int main() {
    std::cout << "--- Windows Passkey Save Reproducer ---" << std::endl;
    
    HWND hwnd = GetConsoleWindow();
    if (!hwnd) {
        hwnd = GetForegroundWindow();
    }

    WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = { 0 };
    rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpInfo.pwszId = L"repro.dotenv-webauthn.local"; 
    rpInfo.pwszName = L"Reproduction Tool";

    BYTE userId[16] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
    WEBAUTHN_USER_ENTITY_INFORMATION userInfo = { 0 };
    userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
    userInfo.cbId = 16;
    userInfo.pbId = userId;
    userInfo.pwszName = L"repro_user";
    userInfo.pwszDisplayName = L"Repro User";

    WEBAUTHN_COSE_CREDENTIAL_PARAMETER alg = { 0 };
    alg.dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
    alg.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    alg.lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pubKeyParams = { 1, &alg };

    std::string jsonClientData = "{\"type\":\"webauthn.create\",\"challenge\":\"cmVwcm8tY2hhbGxlbmdl\",\"origin\":\"https://repro.dotenv-webauthn.local\"}";
    WEBAUTHN_CLIENT_DATA clientData = { 0 };
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = (DWORD)jsonClientData.size();
    clientData.pbClientDataJSON = (PBYTE)jsonClientData.c_str();
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options = { 0 };
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
    
    // THIS TRIGGER THE ERROR ON SOME SYSTEMS:
    options.bRequireResidentKey = TRUE; 
    
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;

    PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = nullptr;
    
    std::cout << "Requesting RESIDENT Passkey (should fail after 2nd biometric)..." << std::endl;
    HRESULT hr = WebAuthNAuthenticatorMakeCredential(hwnd, &rpInfo, &userInfo, &pubKeyParams, &clientData, &options, &pAttestation);

    if (SUCCEEDED(hr)) {
        std::cout << "SUCCESS: This machine supports resident passkeys!" << std::endl;
        WebAuthNFreeCredentialAttestation(pAttestation);
    } else {
        std::cerr << "FAILED: HRESULT 0x" << std::hex << hr << std::endl;
        if (hr == 0x800704c7) std::cout << "Result: User Cancelled (expected if dialog closed)" << std::endl;
        else std::cout << "Result: System error (likely 'Problem saving your passkey')" << std::endl;
    }

    return 0;
}
