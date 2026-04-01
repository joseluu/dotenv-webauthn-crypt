from setuptools import setup, Extension
import pybind11
import os

# Get version from environment or default
VERSION = os.environ.get("PROJECT_VERSION", "0.3.0a6")

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
