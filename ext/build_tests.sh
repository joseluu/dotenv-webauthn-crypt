#!/bin/bash
# Build all standalone C++ test executables using MSVC Build Tools.
# Run from Git Bash:  cd ext && bash build_tests.sh [target]
# Optional target: hmac_secret | device_info | winrt_cred | all (default: all)

set -e

# Prevent Git Bash from converting /flags into C:/Program Files/... paths
export MSYS_NO_PATHCONV=1

MSVC_ROOT="C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.43.34808"
WINSDK="C:/Program Files (x86)/Windows Kits/10"
SDK_VER="10.0.22621.0"

CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"

export INCLUDE="$MSVC_ROOT/include;$WINSDK/Include/$SDK_VER/ucrt;$WINSDK/Include/$SDK_VER/um;$WINSDK/Include/$SDK_VER/shared"
export LIB="$MSVC_ROOT/lib/x64;$WINSDK/Lib/$SDK_VER/ucrt/x64;$WINSDK/Lib/$SDK_VER/um/x64"

COMMON_CL="/EHsc /std:c++17 /Z7 /c /I."

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

TARGET="${1:-all}"

case "$TARGET" in
    hmac_secret)  build_hmac_secret ;;
    device_info)  build_device_info ;;
    winrt_cred)   build_winrt_cred ;;
    all)
        build_hmac_secret
        echo ""
        build_device_info
        echo ""
        build_winrt_cred
        echo ""
        echo "=== All targets built ==="
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Usage: bash build_tests.sh [hmac_secret|device_info|winrt_cred|all]"
        exit 1
        ;;
esac
