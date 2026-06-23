import sys
import os
from setuptools import setup

# Get version from environment or default
VERSION = os.environ.get("PROJECT_VERSION", "0.3.0a7")

# The native C++ extension wraps the Windows WebAuthn API and only builds on
# Windows.  On Linux/macOS the package falls back to the pure-Python browser
# backend (dotenv_webauthn_crypt._browser), so no compiler is required there.
ext_modules = []
if sys.platform == "win32":
    import pybind11
    from setuptools import Extension
    ext_modules = [
        Extension(
            "dotenv_webauthn_crypt._webauthn",
            ["ext/_webauthn.cpp"],
            include_dirs=[pybind11.get_include(), "ext"],
            language="c++",
            libraries=["webauthn", "bcrypt", "user32", "keycredmgr", "ole32", "bthprops"],
            define_macros=[('PROJECT_VERSION', f'"{VERSION}"')]
        ),
    ]

setup(
    ext_modules=ext_modules,
)
