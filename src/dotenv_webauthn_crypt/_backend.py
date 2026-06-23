"""Platform dispatcher for the WebAuthn backend.

``core.py`` and ``cli.py`` import everything WebAuthn-related from here, so they
never have to care whether they run on Windows (native C++ extension) or on
Linux/macOS (browser-driven Python backend).

Both backends expose the same callables.  The only contract that this layer
normalises is ``get_assertion``: every backend returns a ``client_data_hash``
field (the 32-byte hash that was actually signed), so public-key recovery in
``core.py`` is identical everywhere.

  * Windows native: the challenge passed in *is* the client-data that the OS
    hashes, so ``client_data_hash == SHA256(challenge)``.
  * Browser:        the signed hash is ``SHA256(clientDataJSON)``; the browser
    backend computes it and returns it directly.
"""

import sys
import hashlib

if sys.platform == "win32":
    from . import _webauthn as _impl

    # The native module historically targets this RP id (a TPM-backed,
    # non-resident credential is bound to it).
    RP_ID = "credentials.dotenv-webauthn.com"

    get_version = _impl.get_version
    make_credential = _impl.make_credential
    get_platform_status = _impl.get_platform_status

    def get_assertion(rp_id, credential_id, challenge, hint=""):
        result = dict(_impl.get_assertion(rp_id, credential_id, challenge, hint))
        # The native API hashes the supplied client-data bytes with SHA-256.
        result["client_data_hash"] = list(hashlib.sha256(bytes(challenge)).digest())
        return result

else:
    from . import _browser as _impl

    RP_ID = _impl.RP_ID

    get_version = _impl.get_version
    make_credential = _impl.make_credential
    get_assertion = _impl.get_assertion
    get_platform_status = _impl.get_platform_status
