# Scaffolding a Native Win32 C++ Extension for Python

This document summarizes the toolchain, build setup, and key techniques used to
build the native C++ component of **dotenv-webauthn-crypt**  a Windows Hello-backed
security module with no runtime dependencies beyond Windows itself and the Python bridge.

## Toolchain

| Component | Version / Path |
|---|---|
| Compiler | MSVC `cl.exe` 14.43.34808 (C++ 17) |
| Linker | MSVC `link.exe` (same version) |
| Toolchain install | VS 2022 **Build Tools**  `C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.43.34808` |
| Windows SDK | 10.0.22621.0  `C:/Program Files (x86)/Windows Kits/10` |
| Python Bridge | **pybind11**  handles C++ to Python type conversion |

### Why Build Tools, not Visual Studio IDE?

The **Build Tools** edition provides the full MSVC toolchain (`cl.exe`,
`link.exe`, headers, libs) without the IDE overhead. It is required for
compiling the native Python extension (`.pyd`) during `pip install`.

## Build System: Setuptools + pybind11

Unlike standalone apps that use custom bash scripts, this project integrates
directly with the Python ecosystem. The build process is orchestrated by
`setuptools` via `setup.py` and `pyproject.toml`.

### Key Build Steps:
1. **Detection**: `setuptools` locates the MSVC compiler on the system.
2. **Include Paths**: `pybind11.get_include()` is used to provide the necessary
   headers for the Python/C++ interface.
3. **Compilation**: `cl.exe` compiles `ext/native.cpp` into a machine-code object.
4. **Linking**: `link.exe` links against the required Windows System libraries
   (see below) to produce the final `_native.pyd` (a DLL with a Python-compatible entry point).

## Python Interface: pybind11

The interface between Python and C++ is handled by `pybind11`, which eliminates
the need for manual C-API boilerplate.

- **Module Definition**: `PYBIND11_MODULE(_native, m)` defines the extension name.
- **Function Mapping**: `m.def("make_credential", ...)` exposes C++ functions
  directly to Python.
- **Type Conversion**: `pybind11/stl.h` is used to automatically convert
  `std::vector<uint8_t>` to Python `bytes`/`list` and `std::string` to Python `str`.

## Win32 Libraries Used

| Library | Purpose |
|---|---|
| `webauthn.lib` | Core Windows Hello / WebAuthn API calls |
| `bcrypt.lib` | Windows Cryptography Next Generation (CNG) for hashing/entropy |
| `user32.lib` | Required for `GetForegroundWindow` to anchor Hello dialogs |

## Key Win32 Patterns

### Non-Resident Credentials
To maximize compatibility with local TPMs and avoid "Problem saving passkey"
errors, the module uses **Non-Resident Keys**. The TPM generates the key pair,
but the application is responsible for storing the `CredentialID` on disk.

### Window Handle (HWND) Anchor
The WebAuthn API requires a valid `HWND` to display the biometric/PIN prompt.
The extension uses `GetForegroundWindow()` to ensure the dialog appears on top
of the active terminal or IDE.

## Third-Party Dependencies

| Library | License | Integration |
|---|---|---|
| [pybind11](https://github.com/pybind/pybind11) | BSD-style | Used as a build-time dependency to generate the Python extension. |

## Gotchas and Lessons Learned

1. **Strict Field Initialization**: Windows WebAuthn structures (e.g., `WEBAUTHN_CLIENT_DATA`)
   **must** be zero-initialized (`{ 0 }`) or they will return `NTE_INVALID_PARAMETER`.
2. **RP_ID Format**: The Relying Party ID should ideally look like a domain
   (e.g., `localhost` or `myapp.local`) to ensure the platform authenticator
   accepts the request.
3. **Wide Characters**: All Win32 API calls use the `W` (wide-char) variants.
   Internal conversions from UTF-8 `std::string` to `std::wstring` are handled
   via `MultiByteToWideChar`.

## Reproducing This Setup

1. Install [VS Build Tools 2022](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   with the "Desktop development with C++" workload.
2. Ensure Python 3.8+ is installed.
3. Run `pip install .` in the project root.
4. Output: `src/dotenv_webauthn_crypt/_native.cp312-win_amd64.pyd`  the native module.
