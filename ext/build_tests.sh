#!/bin/bash
# Build all standalone C++ test executables using MSVC Build Tools.
# Run from Git Bash:  cd ext && bash build_tests.sh [target] [vs_version]
# Optional target: hmac_secret | device_info | cross_platform | winrt_cred | all (default: all)
# Optional vs_version: vs2015 | vs2022 (default: auto-detect or vs2022)
#
# Examples:
#   bash build_tests.sh cross_platform        # Auto-detect or use VS2022
#   bash build_tests.sh cross_platform vs2015 # Force VS2015
#   bash build_tests.sh all vs2022            # Force VS2022

set -e

# Prevent Git Bash from converting /flags into C:/Program Files/... paths
export MSYS_NO_PATHCONV=1

# Determine Visual Studio version to use
VS_VERSION="${2:-auto}"

# Auto-detect if not specified
if [ "$VS_VERSION" = "auto" ]; then
    if [ -d "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools" ]; then
        VS_VERSION="vs2022"
    elif [ -d "C:/Program Files (x86)/Microsoft Visual Studio 14.0" ]; then
        VS_VERSION="vs2015"
    else
        echo "ERROR: No supported Visual Studio installation found."
        echo "Please specify vs2015 or vs2022 manually."
        exit 1
    fi
fi

echo "Using Visual Studio version: $VS_VERSION"
echo ""

# Configure paths based on Visual Studio version
if [ "$VS_VERSION" = "vs2015" ]; then
    # ===== Visual Studio 2015 (VS 14.0) Configuration =====
    MSVC_ROOT="C:/Program Files (x86)/Microsoft Visual Studio 14.0/VC"
    WINSDK="C:/Program Files (x86)/Windows Kits/10"
    SDK_VER="10.0.17763.0"

    CL="$MSVC_ROOT/bin/amd64/cl.exe"
    LINK="$MSVC_ROOT/bin/amd64/link.exe"

    export INCLUDE="$MSVC_ROOT/include;$MSVC_ROOT/atlmfc/include;$WINSDK/Include/$SDK_VER/ucrt;$WINSDK/Include/$SDK_VER/um;$WINSDK/Include/$SDK_VER/shared"
    export LIB="$MSVC_ROOT/lib/amd64;$MSVC_ROOT/atlmfc/lib/amd64;$WINSDK/Lib/$SDK_VER/ucrt/x64;$WINSDK/Lib/$SDK_VER/um/x64"

    # VS2015 doesn't support /std:c++17
    COMMON_CL="/EHsc /Z7 /c /I."

    # Check if webauthn.lib exists, create if needed
    if [ ! -f "webauthn.lib" ]; then
        echo "webauthn.lib not found. Creating import library..."
        if [ ! -f "webauthn.def" ]; then
            cat > webauthn.def << 'EOF'
LIBRARY webauthn
EXPORTS
    WebAuthNGetApiVersionNumber
    WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable
    WebAuthNAuthenticatorMakeCredential
    WebAuthNAuthenticatorGetAssertion
    WebAuthNFreeCredentialAttestation
    WebAuthNFreeAssertion
    WebAuthNGetCancellationId
    WebAuthNCancelCurrentOperation
    WebAuthNGetErrorName
    WebAuthNGetW3CExceptionDOMError
    WebAuthNGetPlatformCredentialList
    WebAuthNFreePlatformCredentialList
    WebAuthNDeletePlatformCredential
    WebAuthNGetAuthenticatorList
    WebAuthNFreeAuthenticatorList
EOF
        fi
        "$MSVC_ROOT/bin/amd64/lib.exe" /DEF:webauthn.def /MACHINE:X64 /OUT:webauthn.lib > /dev/null 2>&1
        echo "webauthn.lib created successfully."
        echo ""
    fi

elif [ "$VS_VERSION" = "vs2022" ]; then
    # ===== Visual Studio 2022 Build Tools Configuration =====
    MSVC_ROOT="C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.43.34808"
    WINSDK="C:/Program Files (x86)/Windows Kits/10"
    SDK_VER="10.0.22621.0"

    CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
    LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"

    export INCLUDE="$MSVC_ROOT/include;$WINSDK/Include/$SDK_VER/ucrt;$WINSDK/Include/$SDK_VER/um;$WINSDK/Include/$SDK_VER/shared"
    export LIB="$MSVC_ROOT/lib/x64;$WINSDK/Lib/$SDK_VER/ucrt/x64;$WINSDK/Lib/$SDK_VER/um/x64"

    # VS2022 supports /std:c++17
    COMMON_CL="/EHsc /std:c++17 /Z7 /c /I."

else
    echo "ERROR: Unknown Visual Studio version: $VS_VERSION"
    echo "Supported versions: vs2015, vs2022"
    exit 1
fi

# Verify compiler exists
if [ ! -f "$CL" ]; then
    echo "ERROR: Compiler not found at: $CL"
    echo "Please check your Visual Studio installation."
    exit 1
fi

build_hmac_secret() {
    echo "=== Building test_hmac_secret ==="
    "$CL" $COMMON_CL test_hmac_secret.cpp
    "$LINK" test_hmac_secret.obj webauthn.lib user32.lib /OUT:test_hmac_secret.exe
    rm -f test_hmac_secret.obj
    echo "  -> test_hmac_secret.exe"
}

build_device_info() {
    echo "=== Building test_device_info ==="
    "$CL" $COMMON_CL test_device_info.cpp
    "$LINK" test_device_info.obj webauthn.lib user32.lib /OUT:test_device_info.exe
    rm -f test_device_info.obj
    echo "  -> test_device_info.exe"
}

build_cross_platform() {
    echo "=== Building test_cross_platform ==="
    "$CL" $COMMON_CL test_cross_platform.cpp
    "$LINK" test_cross_platform.obj webauthn.lib user32.lib /OUT:test_cross_platform.exe
    rm -f test_cross_platform.obj
    echo "  -> test_cross_platform.exe"
}

build_winrt_cred() {
    echo "=== Building test_winrt_cred ==="
    # Requires C++/WinRT headers (cppwinrt NuGet or VS workload)
    if ! "$CL" $COMMON_CL /await test_winrt_cred.cpp 2>&1; then
        echo "  SKIPPED — C++/WinRT headers not found (install cppwinrt NuGet or 'C++ Universal Windows Platform tools')"
        return 0
    fi
    "$LINK" test_winrt_cred.obj windowsapp.lib keycredmgr.lib user32.lib /OUT:test_winrt_cred.exe
    rm -f test_winrt_cred.obj
    echo "  -> test_winrt_cred.exe"
}

# Parse target (first argument, or 'all' if not specified or if it's a VS version)
TARGET="${1:-all}"
if [ "$TARGET" = "vs2015" ] || [ "$TARGET" = "vs2022" ]; then
    TARGET="all"
fi

case "$TARGET" in
    hmac_secret)     build_hmac_secret ;;
    device_info)     build_device_info ;;
    cross_platform)  build_cross_platform ;;
    winrt_cred)      build_winrt_cred ;;
    all)
        build_hmac_secret
        echo ""
        build_device_info
        echo ""
        build_cross_platform
        echo ""
        build_winrt_cred
        echo ""
        echo "=== All targets built ==="
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Usage: bash build_tests.sh [target] [vs_version]"
        echo "  target:     hmac_secret | device_info | cross_platform | winrt_cred | all (default: all)"
        echo "  vs_version: vs2015 | vs2022 (default: auto-detect)"
        echo ""
        echo "Examples:"
        echo "  bash build_tests.sh cross_platform"
        echo "  bash build_tests.sh cross_platform vs2015"
        echo "  bash build_tests.sh all vs2022"
        exit 1
        ;;
esac
