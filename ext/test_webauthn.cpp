#include <windows.h>
#include <webauthn.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <iomanip>
#include <ctime>

#pragma comment(lib, "webauthn.lib")

void print_hr(const char* label, HRESULT hr) {
    std::cerr << label << " HRESULT: 0x" << std::hex << std::setw(8) << std::setfill('0') << (unsigned long)hr << std::dec;
    PCWSTR errName = WebAuthNGetErrorName(hr);
    if (errName) {
        std::wcerr << L"  (" << errName << L")";
    }
    std::cerr << std::endl;
}

void print_separator(const char* title) {
    std::cout << std::endl << "========== " << title << " ==========" << std::endl;
}

bool try_make_credential(HWND hwnd, DWORD optionsVersion, BOOL residentKey,
                         DWORD attachment, const char* attachmentName,
                         LPCWSTR rpId, LPCWSTR rpName,
                         const char* description) {
    print_separator(description);

    // Generate fresh user ID each time
    time_t now = time(nullptr);
    BYTE userId[16];
    memset(userId, 0, 16);
    memcpy(userId, &now, sizeof(now));
    userId[8] = (BYTE)(rand() & 0xFF);
    userId[9] = (BYTE)(rand() & 0xFF);

    WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = { 0 };
    rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpInfo.pwszId = rpId;
    rpInfo.pwszName = rpName;

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

    // Raw challenge (like _webauthn.cpp)
    BYTE challenge[32];
    memset(challenge, 0xEE, 32);
    WEBAUTHN_CLIENT_DATA clientData = { 0 };
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = 32;
    clientData.pbClientDataJSON = challenge;
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options = { 0 };
    options.dwVersion = optionsVersion;
    options.dwTimeoutMilliseconds = 120000;
    options.dwAuthenticatorAttachment = attachment;
    options.bRequireResidentKey = residentKey;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;

    std::wcout << L"  RP ID:                " << rpId << std::endl;
    std::cout << "  Attachment:           " << attachmentName << std::endl;
    std::cout << "  Options version:      " << optionsVersion << std::endl;
    std::cout << "  bRequireResidentKey:  " << (residentKey ? "TRUE" : "FALSE") << std::endl;
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
        if (pAttestation->pwszFormatType) {
            std::wcout << pAttestation->pwszFormatType;
        } else {
            std::cout << "(null)";
        }
        std::cout << std::endl;
        std::cout << "  dwUsedTransport:         " << pAttestation->dwUsedTransport << std::endl;
        // Decode transport
        DWORD t = pAttestation->dwUsedTransport;
        if (t & WEBAUTHN_CTAP_TRANSPORT_USB)       std::cout << "    -> USB" << std::endl;
        if (t & WEBAUTHN_CTAP_TRANSPORT_NFC)       std::cout << "    -> NFC" << std::endl;
        if (t & WEBAUTHN_CTAP_TRANSPORT_BLE)       std::cout << "    -> BLE" << std::endl;
        if (t & WEBAUTHN_CTAP_TRANSPORT_INTERNAL)  std::cout << "    -> INTERNAL (platform)" << std::endl;

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
    std::cout << "=== WebAuthn Platform Credential Test Suite v2 ===" << std::endl;

    // --- Diagnostics ---
    print_separator("DIAGNOSTICS");
    DWORD apiVersion = WebAuthNGetApiVersionNumber();
    std::cout << "WebAuthN API version:   " << apiVersion << std::endl;

    BOOL platformAvail = FALSE;
    WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&platformAvail);
    std::cout << "Platform authenticator: " << (platformAvail ? "AVAILABLE" : "NOT AVAILABLE") << std::endl;

    HWND hwnd = GetConsoleWindow();
    if (!hwnd) hwnd = GetForegroundWindow();
    std::cout << "Window handle (HWND):   0x" << std::hex << (uintptr_t)hwnd << std::dec << std::endl;

    // -------------------------------------------------------
    // TEST 1: PLATFORM + real-looking domain (matches working Python code)
    // -------------------------------------------------------
    if (try_make_credential(hwnd, 4, FALSE,
            WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM, "PLATFORM",
            L"credentials.dotenv-webauthn.com", L"Dotenv WebAuthn Crypt",
            "TEST 1: PLATFORM + credentials.dotenv-webauthn.com (same as Python)")) {
        std::cout << "\n>>> RP ID format matters! Real domain works with PLATFORM." << std::endl;
        return 0;
    }

    // -------------------------------------------------------
    // TEST 2: ANY attachment + real domain (let Windows choose)
    //   If Windows shows both options and you pick Hello -> platform works
    // -------------------------------------------------------
    if (try_make_credential(hwnd, 4, FALSE,
            WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY, "ANY",
            L"credentials.dotenv-webauthn.com", L"Dotenv WebAuthn Crypt",
            "TEST 2: ANY attachment + credentials.dotenv-webauthn.com")) {
        std::cout << "\n>>> ANY attachment works! Check dwUsedTransport above." << std::endl;
        return 0;
    }

    // -------------------------------------------------------
    // TEST 3: PLATFORM + localhost (another valid-ish domain)
    // -------------------------------------------------------
    if (try_make_credential(hwnd, 4, FALSE,
            WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM, "PLATFORM",
            L"localhost", L"Localhost Test",
            "TEST 3: PLATFORM + localhost")) {
        std::cout << "\n>>> localhost works with PLATFORM." << std::endl;
        return 0;
    }

    // -------------------------------------------------------
    // TEST 4: PLATFORM + gitlab.com (known working domain from browser)
    // -------------------------------------------------------
    if (try_make_credential(hwnd, 4, FALSE,
            WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM, "PLATFORM",
            L"gitlab.com", L"GitLab",
            "TEST 4: PLATFORM + gitlab.com (known working from browser)")) {
        std::cout << "\n>>> gitlab.com works outside browser too!" << std::endl;
        return 0;
    }

    // -------------------------------------------------------
    // TEST 5: CROSS_PLATFORM + real domain (sanity check - should work)
    //   This is what your Python code does today. Cancel if phone prompt appears.
    // -------------------------------------------------------
    std::cout << std::endl << "NOTE: Test 5 uses CROSS_PLATFORM - will prompt for phone/QR." << std::endl;
    std::cout << "Cancel it if you just want to confirm the pattern." << std::endl;
    if (try_make_credential(hwnd, 4, FALSE,
            WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM, "CROSS_PLATFORM",
            L"credentials.dotenv-webauthn.com", L"Dotenv WebAuthn Crypt",
            "TEST 5: CROSS_PLATFORM + credentials.dotenv-webauthn.com (sanity check)")) {
        std::cout << "\n>>> CROSS_PLATFORM works as expected (baseline)." << std::endl;
        return 0;
    }

    std::cerr << std::endl << "All tests failed." << std::endl;
    return 1;
}
