"""Build script for the test WebAuthn pybind11 module."""
from setuptools import setup, Extension
import pybind11

ext_modules = [
    Extension(
        "_test_webauthn",
        ["ext/test_webauthn_module.cpp"],
        include_dirs=[pybind11.get_include()],
        language="c++",
        libraries=["webauthn", "user32"],
    ),
]

setup(
    name="test-webauthn-module",
    ext_modules=ext_modules,
)
