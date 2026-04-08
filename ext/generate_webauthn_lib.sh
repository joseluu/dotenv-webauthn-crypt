#!/bin/bash
# generate_webauthn_lib.sh
#
# Generates webauthn.lib import library from webauthn.dll
# This is needed for older Visual Studio versions (VS2015) that don't include
# webauthn.lib in their Windows SDK.
#
# Usage:
#   bash generate_webauthn_lib.sh [vs_version]
#
# Parameters:
#   vs_version: vs2015 | vs2022 (default: auto-detect)
#
# Examples:
#   bash generate_webauthn_lib.sh           # Auto-detect VS version
#   bash generate_webauthn_lib.sh vs2015    # Use VS2015 lib.exe
#   bash generate_webauthn_lib.sh vs2022    # Use VS2022 lib.exe
 
set -e
 
# Prevent Git Bash from converting /flags into C:/Program Files/... paths
export MSYS_NO_PATHCONV=1
 
echo "================================================================"
echo "  WebAuthn Import Library Generator"
echo "================================================================"
echo ""
 
# Determine Visual Studio version to use
VS_VERSION="${1:-auto}"
 
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
 
# Set lib.exe path based on Visual Studio version
if [ "$VS_VERSION" = "vs2015" ]; then
    LIB_EXE="C:/Program Files (x86)/Microsoft Visual Studio 14.0/VC/bin/amd64/lib.exe"
elif [ "$VS_VERSION" = "vs2022" ]; then
    LIB_EXE="C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.43.34808/bin/Hostx64/x64/lib.exe"
else
    echo "ERROR: Unknown Visual Studio version: $VS_VERSION"
    echo "Supported versions: vs2015, vs2022"
    exit 1
fi
 
# Verify lib.exe exists
if [ ! -f "$LIB_EXE" ]; then
    echo "ERROR: lib.exe not found at: $LIB_EXE"
    echo "Please check your Visual Studio installation."
    exit 1
fi
 
echo "Using lib.exe: $LIB_EXE"
echo ""
 
# Check if webauthn.dll exists
WEBAUTHN_DLL="C:/Windows/System32/webauthn.dll"
if [ ! -f "$WEBAUTHN_DLL" ]; then
    echo "ERROR: webauthn.dll not found at: $WEBAUTHN_DLL"
    echo "WebAuthn is not available on this system."
    echo "Requires Windows 10 version 1903 (May 2019 Update) or later."
    exit 1
fi
 
echo "Found webauthn.dll: $WEBAUTHN_DLL"
echo ""
 
# Create webauthn.def if it doesn't exist or if user wants to regenerate
if [ -f "webauthn.def" ]; then
    echo "webauthn.def already exists."
    read -p "Regenerate it? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Using existing webauthn.def"
    else
        rm -f webauthn.def
    fi
fi
 
if [ ! -f "webauthn.def" ]; then
    echo "Creating webauthn.def..."
    cat > webauthn.def << 'EOF'
LIBRARY webauthn
EXPORTS
    ; Core API functions (API v1+)
    WebAuthNGetApiVersionNumber
    WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable
    WebAuthNAuthenticatorMakeCredential
    WebAuthNAuthenticatorGetAssertion
    WebAuthNFreeCredentialAttestation
    WebAuthNFreeAssertion
 
    ; Cancellation support (API v2+)
    WebAuthNGetCancellationId
    WebAuthNCancelCurrentOperation
 
    ; Error handling (API v3+)
    WebAuthNGetErrorName
    WebAuthNGetW3CExceptionDOMError
 
    ; Platform credential management (API v4+)
    WebAuthNGetPlatformCredentialList
    WebAuthNFreePlatformCredentialList
    WebAuthNDeletePlatformCredential
 
    ; Authenticator enumeration (API v9+)
    WebAuthNGetAuthenticatorList
    WebAuthNFreeAuthenticatorList
EOF
    echo "✓ webauthn.def created"
else
    echo "✓ Using existing webauthn.def"
fi
 
echo ""
 
# Backup existing files if they exist
if [ -f "webauthn.lib" ]; then
    echo "Backing up existing webauthn.lib to webauthn.lib.bak"
    cp webauthn.lib webauthn.lib.bak
fi
 
if [ -f "webauthn.exp" ]; then
    echo "Backing up existing webauthn.exp to webauthn.exp.bak"
    cp webauthn.exp webauthn.exp.bak
fi
 
echo ""
echo "Generating import library..."
echo "Running: lib.exe /DEF:webauthn.def /MACHINE:X64 /OUT:webauthn.lib"
echo ""
 
# Generate the import library
if "$LIB_EXE" /DEF:webauthn.def /MACHINE:X64 /OUT:webauthn.lib > lib_output.txt 2>&1; then
    echo "================================================================"
    echo "  ✓ SUCCESS"
    echo "================================================================"
    echo ""
    echo "Generated files:"
 
    if [ -f "webauthn.lib" ]; then
        LIB_SIZE=$(stat -c%s "webauthn.lib" 2>/dev/null || stat -f%z "webauthn.lib" 2>/dev/null || echo "unknown")
        echo "  ✓ webauthn.lib ($LIB_SIZE bytes)"
    fi
 
    if [ -f "webauthn.exp" ]; then
        EXP_SIZE=$(stat -c%s "webauthn.exp" 2>/dev/null || stat -f%z "webauthn.exp" 2>/dev/null || echo "unknown")
        echo "  ✓ webauthn.exp ($EXP_SIZE bytes)"
    fi
 
    if [ -f "webauthn.def" ]; then
        DEF_SIZE=$(stat -c%s "webauthn.def" 2>/dev/null || stat -f%z "webauthn.def" 2>/dev/null || echo "unknown")
        echo "  ✓ webauthn.def ($DEF_SIZE bytes)"
    fi
 
    echo ""
    echo "The import library is ready to use with your builds."
    echo "You can now compile projects that link against webauthn.lib"
    echo ""
 
    # Show lib.exe output if verbose
    if [ -f "lib_output.txt" ]; then
        echo "lib.exe output:"
        cat lib_output.txt
        rm -f lib_output.txt
    fi
 
    exit 0
else
    echo "================================================================"
    echo "  ✗ FAILED"
    echo "================================================================"
    echo ""
    echo "Failed to generate import library."
    echo ""
 
    if [ -f "lib_output.txt" ]; then
        echo "lib.exe output:"
        cat lib_output.txt
        rm -f lib_output.txt
    fi
 
    echo ""
    echo "Troubleshooting:"
    echo "  1. Verify Visual Studio is properly installed"
    echo "  2. Check that lib.exe exists at: $LIB_EXE"
    echo "  3. Ensure webauthn.def is valid"
    echo "  4. Try running with administrator privileges"
    echo ""
 
    exit 1
fi
