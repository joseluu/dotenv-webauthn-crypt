import os
from setuptools import setup, Extension
import pybind11

ext_modules = [
    Extension(
        "dotenv_webauthn_crypt._native",
        ["ext/native.cpp"],
        include_dirs=[pybind11.get_include()],
        language="c++",
        libraries=["webauthn", "bcrypt", "user32"],
    ),
]

setup(
    ext_modules=ext_modules,
)
