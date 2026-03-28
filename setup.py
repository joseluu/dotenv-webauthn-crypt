from setuptools import setup, Extension
import pybind11
import os

# Get version from environment or default
VERSION = os.environ.get("PROJECT_VERSION", "0.3.0a1")

ext_modules = [
    Extension(
        "dotenv_webauthn_crypt._native",
        ["ext/native.cpp"],
        include_dirs=[pybind11.get_include()],
        language="c++",
        libraries=["webauthn", "bcrypt", "user32"],
        define_macros=[('PROJECT_VERSION', f'"{VERSION}"')]
    ),
]

setup(
    ext_modules=ext_modules,
)
