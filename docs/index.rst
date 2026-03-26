Welcome to dotenv-webauthn-crypt's documentation!
================================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

🚀 Introduction
--------------

``dotenv-webauthn-crypt`` is a drop-in replacement for ``python-dotenv`` that enhances security by keeping environment variables encrypted at rest and gating access behind **Windows Hello (Biometrics/PIN)**.

🛠 Installation
--------------

.. code-block:: powershell

   pip install dotenv-webauthn-crypt

📖 Usage
--------

Initialization
~~~~~~~~~~~~~~

Create your machine-specific root credential in the TPM:

.. code-block:: powershell

   dotenv-webauthn-crypt-cli init --user MyWindowsUser

Encryption
~~~~~~~~~~

Encrypt an existing ``.env`` file:

.. code-block:: powershell

   dotenv-webauthn-crypt-cli encrypt .env

Python API
~~~~~~~~~~

.. code-block:: python

   from dotenv_webauthn_crypt import load_dotenv
   load_dotenv()

🔒 Security Model
----------------

1. **Root Credential**: Stored in the Windows TPM via WebAuthn.
2. **Key Derivation**: Uses HKDF-SHA256 with a TPM-backed signature as the master key.
3. **Encryption**: AES-256-GCM authenticated encryption.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
