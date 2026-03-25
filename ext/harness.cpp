#include <windows.h>
#include <webauthn.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <string>

#pragma comment(lib, "webauthn.lib")

int main() {
    std::cout << "--- WebAuthn Passkey Save Test (Strict Compliance) ---" << std::endl;
    
    // 1. Get a solid window handle
    HWND hwnd = GetConsoleWindow();
    if (!hwnd) {
        hwnd = GetForegroundWindow();
    }

    // 2. RP Information - Use a unique, local domain
    WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = { 0 };
    rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpInfo.pwszId = L"dotenv-vault.local"; 
    rpInfo.pwszName = L"Dotenv Vault";

    // 3. User Information - Use a unique ID to avoid collisions
    BYTE userId[16] = { 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05 };
    WEBAUTHN_USER_ENTITY_INFORMATION userInfo = { 0 };
    userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
    userInfo.cbId = 16;
    userInfo.pbId = userId;
    userInfo.pwszName = L"vault_user";
    userInfo.pwszDisplayName = L"Vault User";

    // 4. Credential Parameters
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER alg = { 0 };
    alg.dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
    alg.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    alg.lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pubKeyParams = { 1, &alg };

    // 5. Client Data - MUST be valid JSON for a passkey save
    std::string jsonClientData = "{\"type\":\"webauthn.create\",\"challenge\":\"Y2hhbGxlbmdl\",\"origin\":\"https://dotenv-vault.local\"}";
    
    WEBAUTHN_CLIENT_DATA clientData = { 0 };
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = (DWORD)jsonClientData.size();
    clientData.pbClientDataJSON = (PBYTE)jsonClientData.c_str();
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    // 6. Make Credential Options
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options = { 0 };
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
    
    // THIS MUST BE TRUE FOR A PASSKEY SAVE
    options.bRequireResidentKey = TRUE; 
    
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;

    PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = nullptr;
    
    std::cout << "Requesting Passkey Creation (Windows Hello)..." << std::endl;
    HRESULT hr = WebAuthNAuthenticatorMakeCredential(
        hwnd, 
        &rpInfo, 
        &userInfo, 
        &pubKeyParams, 
        &clientData, 
        &options, 
        &pAttestation
    );

    if (SUCCEEDED(hr)) {
        std::cout << "SUCCESS: Passkey saved to TPM!" << std::endl;
        
        std::ofstream outfile("test_credentialid.bin", std::ios::binary);
        outfile.write(reinterpret_cast<const char*>(pAttestation->pbCredentialId), pAttestation->cbCredentialId);
        outfile.close();
        
        std::cout << "Saved " << pAttestation->cbCredentialId << " bytes to test_credentialid.bin" << std::endl;
        WebAuthNFreeCredentialAttestation(pAttestation);
    } else {
        std::cerr << "FAILED: HRESULT 0x" << std::hex << hr << std::endl;
        if (hr == 0x80090027) {
            std::cerr << "Error: Invalid Parameter. Try a different RP ID or clear your TPM metadata." << std::endl;
        }
    }

    return 0;
}
