// Test WinRT KeyCredentialManager + Win32 keycredmgr.h from desktop app
// Goal: diagnose NGC state and attempt provisioning
//
// Build (from Git Bash, response files):
//   cl /std:c++17 /EHsc /Z7 /c test_winrt_cred.cpp
//   link test_winrt_cred.obj WindowsApp.lib keycredmgr.lib user32.lib

#pragma comment(lib, "windowsapp")
#pragma comment(lib, "keycredmgr")
#pragma comment(lib, "user32")

#include <windows.h>
#include <keycredmgr.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Storage.Streams.h>
#include <iostream>
#include <iomanip>

using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Credentials;

// ---------------------------------------------------------------------------
// Test 1: Win32 keycredmgr.h — check NGC operation readiness
// ---------------------------------------------------------------------------
void test_keycredmgr_status() {
    std::cout << "========== Win32 KeyCredentialManager Status ==========" << std::endl;

    BOOL isReady = FALSE;
    KeyCredentialManagerOperationErrorStates errorStates = KeyCredentialManagerOperationErrorStateNone;

    HRESULT hr = KeyCredentialManagerGetOperationErrorStates(
        KeyCredentialManagerProvisioning, &isReady, &errorStates);

    std::cout << "  KeyCredentialManagerGetOperationErrorStates (Provisioning):" << std::endl;
    std::cout << "    HRESULT:     0x" << std::hex << (unsigned long)hr << std::dec << std::endl;
    std::cout << "    isReady:     " << (isReady ? "YES" : "NO") << std::endl;
    std::cout << "    errorStates: 0x" << std::hex << (unsigned long)errorStates << std::dec << std::endl;

    if (errorStates & KeyCredentialManagerOperationErrorStateDeviceJoinFailure)
        std::cout << "      -> DeviceJoinFailure (0x01)" << std::endl;
    if (errorStates & KeyCredentialManagerOperationErrorStateTokenFailure)
        std::cout << "      -> TokenFailure (0x02)" << std::endl;
    if (errorStates & KeyCredentialManagerOperationErrorStateCertificateFailure)
        std::cout << "      -> CertificateFailure (0x04)" << std::endl;
    if (errorStates & KeyCredentialManagerOperationErrorStateRemoteSessionFailure)
        std::cout << "      -> RemoteSessionFailure (0x08)" << std::endl;
    if (errorStates & KeyCredentialManagerOperationErrorStatePolicyFailure)
        std::cout << "      -> PolicyFailure (0x10)" << std::endl;
    if (errorStates & KeyCredentialManagerOperationErrorStateHardwareFailure)
        std::cout << "      -> HardwareFailure (0x20)" << std::endl;
    if (errorStates & KeyCredentialManagerOperationErrorStatePinExistsFailure)
        std::cout << "      -> PinExistsFailure (0x40)" << std::endl;
    if (errorStates == KeyCredentialManagerOperationErrorStateNone)
        std::cout << "      -> None (no errors)" << std::endl;

    // Also check for PinChange and PinReset operations
    BOOL isReadyPinChange = FALSE;
    KeyCredentialManagerOperationErrorStates errorStatesPinChange = KeyCredentialManagerOperationErrorStateNone;
    KeyCredentialManagerGetOperationErrorStates(
        KeyCredentialManagerPinChange, &isReadyPinChange, &errorStatesPinChange);
    std::cout << std::endl;
    std::cout << "  PinChange operation:" << std::endl;
    std::cout << "    isReady:     " << (isReadyPinChange ? "YES" : "NO") << std::endl;
    std::cout << "    errorStates: 0x" << std::hex << (unsigned long)errorStatesPinChange << std::dec << std::endl;

    // Get NGC container info
    std::cout << std::endl;
    std::cout << "  KeyCredentialManagerGetInformation:" << std::endl;
    KeyCredentialManagerInfo* info = nullptr;
    hr = KeyCredentialManagerGetInformation(&info);
    std::cout << "    HRESULT: 0x" << std::hex << (unsigned long)hr << std::dec << std::endl;
    if (SUCCEEDED(hr) && info) {
        OLECHAR guidStr[40];
        StringFromGUID2(info->containerId, guidStr, 40);
        std::wcout << L"    NGC Container ID: " << guidStr << std::endl;
        KeyCredentialManagerFreeInformation(info);
    } else {
        std::cout << "    (no NGC container — not provisioned)" << std::endl;
    }
}

// ---------------------------------------------------------------------------
// Test 2: Win32 keycredmgr.h — attempt NGC provisioning
// ---------------------------------------------------------------------------
void test_keycredmgr_provision(HWND hwnd) {
    std::cout << std::endl << "========== Attempt NGC Provisioning ==========" << std::endl;
    std::cout << "  HWND: 0x" << std::hex << (uintptr_t)hwnd << std::dec << std::endl;
    std::cout << "  Calling KeyCredentialManagerShowUIOperation(Provisioning)..." << std::endl;
    std::cout << "  (A Windows Hello setup dialog may appear)" << std::endl;

    HRESULT hr = KeyCredentialManagerShowUIOperation(hwnd, KeyCredentialManagerProvisioning);

    std::cout << "  Result: 0x" << std::hex << (unsigned long)hr << std::dec << std::endl;
    if (SUCCEEDED(hr)) {
        std::cout << "  => SUCCESS! NGC may now be provisioned." << std::endl;
    } else {
        std::cout << "  => FAILED" << std::endl;
        if (hr == (HRESULT)0x800704C7)  std::cout << "    ERROR_CANCELLED" << std::endl;
        if (hr == (HRESULT)0x80090029)  std::cout << "    NTE_NOT_SUPPORTED" << std::endl;
        if (hr == (HRESULT)0x80070005)  std::cout << "    ACCESS_DENIED" << std::endl;
        if (hr == (HRESULT)0x8000FFFF)  std::cout << "    E_UNEXPECTED" << std::endl;
    }

    // Re-check status after provisioning attempt
    BOOL isReady = FALSE;
    KeyCredentialManagerOperationErrorStates errorStates = KeyCredentialManagerOperationErrorStateNone;
    KeyCredentialManagerGetOperationErrorStates(
        KeyCredentialManagerProvisioning, &isReady, &errorStates);
    std::cout << "  After provisioning attempt:" << std::endl;
    std::cout << "    isReady:     " << (isReady ? "YES" : "NO") << std::endl;
    std::cout << "    errorStates: 0x" << std::hex << (unsigned long)errorStates << std::dec << std::endl;
}

// ---------------------------------------------------------------------------
// Test 3: WinRT KeyCredentialManager::IsSupportedAsync
// ---------------------------------------------------------------------------
void test_winrt_supported() {
    std::cout << std::endl << "========== WinRT KeyCredentialManager ==========" << std::endl;

    try {
        bool supported = KeyCredentialManager::IsSupportedAsync().get();
        std::cout << "  IsSupportedAsync: " << (supported ? "YES" : "NO") << std::endl;
    } catch (winrt::hresult_error const& ex) {
        std::wcerr << L"  IsSupportedAsync error: " << ex.message().c_str()
                   << L" (0x" << std::hex << (uint32_t)ex.code() << L")" << std::endl;
    }
}

// ---------------------------------------------------------------------------
// Test 4: WinRT KeyCredentialManager::RequestCreateAsync
//   Creates an RSA 2048 key (NOT FIDO2) — just to test if Hello key creation works
//   NOTE: Dialog may appear BEHIND the window (no HWND interop for this API)
// ---------------------------------------------------------------------------
void test_winrt_create() {
    std::cout << std::endl << "========== WinRT RequestCreateAsync ==========" << std::endl;
    std::cout << "  NOTE: Dialog may appear behind this window — check taskbar!" << std::endl;
    std::cout << "  This creates an RSA key (NOT FIDO2) — just testing NGC path." << std::endl;

    try {
        auto result = KeyCredentialManager::RequestCreateAsync(
            L"dotenv-webauthn-test-key",
            KeyCredentialCreationOption::ReplaceExisting
        ).get();

        std::cout << "  Status: ";
        switch (result.Status()) {
            case KeyCredentialStatus::Success: {
                std::cout << "SUCCESS" << std::endl;
                auto cred = result.Credential();
                std::wcout << L"  Name: " << cred.Name().c_str() << std::endl;
                auto pubkey = cred.RetrievePublicKey();
                std::cout << "  Public key size: " << pubkey.Length() << " bytes" << std::endl;

                // Clean up
                KeyCredentialManager::DeleteAsync(L"dotenv-webauthn-test-key").get();
                std::cout << "  (Test key deleted)" << std::endl;
                break;
            }
            case KeyCredentialStatus::UserCanceled:
                std::cout << "USER_CANCELED" << std::endl; break;
            case KeyCredentialStatus::NotFound:
                std::cout << "NOT_FOUND" << std::endl; break;
            case KeyCredentialStatus::UserPrefersPassword:
                std::cout << "USER_PREFERS_PASSWORD" << std::endl; break;
            case KeyCredentialStatus::CredentialAlreadyExists:
                std::cout << "CREDENTIAL_ALREADY_EXISTS" << std::endl; break;
            case KeyCredentialStatus::SecurityDeviceLocked:
                std::cout << "SECURITY_DEVICE_LOCKED" << std::endl; break;
            default:
                std::cout << "UNKNOWN (" << (int)result.Status() << ")" << std::endl;
        }
    } catch (winrt::hresult_error const& ex) {
        std::wcerr << L"  Error: " << ex.message().c_str()
                   << L" (0x" << std::hex << (uint32_t)ex.code() << L")" << std::endl;
    }
}

int main() {
    std::cout << "=== NGC Diagnostics & Provisioning Test ===" << std::endl;

    winrt::init_apartment();

    HWND hwnd = GetForegroundWindow();
    if (!hwnd) hwnd = GetConsoleWindow();
    std::cout << "HWND: 0x" << std::hex << (uintptr_t)hwnd << std::dec << std::endl;

    // Step 1: Check NGC status
    test_keycredmgr_status();

    // Step 2: Check WinRT support
    test_winrt_supported();

    // Step 3: Attempt NGC provisioning (may trigger Windows Hello setup)
    test_keycredmgr_provision(hwnd);

    // Step 4: Try WinRT key creation (tests if NGC works after provisioning)
    test_winrt_create();

    // Final status
    std::cout << std::endl << "========== Final NGC Status ==========" << std::endl;
    test_keycredmgr_status();

    return 0;
}
