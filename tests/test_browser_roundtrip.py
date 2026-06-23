"""End-to-end crypto test for the browser backend path (no browser required).

Simulates a P-256 authenticator in pure Python and drives the real ``core.py``
code so we exercise:

  * public-key parsing from attested credential data (make_credential path),
  * public-key recovery from an assertion signature using a *clientDataJSON*
    hash (the browser convention, ``SHA256(clientDataJSON)``), and
  * the full encrypt -> load_dotenv decrypt round trip.

The native Windows module is unavailable on CI/Linux, so we monkeypatch the
backend with a deterministic simulated authenticator.
"""

import os
import json
import base64
import hashlib
import struct
import tempfile
import unittest

import cbor2
from ecdsa import SigningKey, NIST256p
from ecdsa.util import sigencode_der

from dotenv_webauthn_crypt import core


RP_ID = "localhost"


def _build_attested_authenticator_data(vk, credential_id: bytes) -> bytes:
    """authenticatorData with attested credential data (AT flag), as returned
    by navigator.credentials.create().getAuthenticatorData()."""
    rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
    flags = 0x45  # UP | UV | AT
    sign_count = struct.pack(">I", 0)
    aaguid = bytes(16)  # all-zero for a software/simulated authenticator

    point = vk.pubkey.point
    x = point.x().to_bytes(32, "big")
    y = point.y().to_bytes(32, "big")
    cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})

    att_cred_data = (aaguid
                     + struct.pack(">H", len(credential_id))
                     + credential_id
                     + cose_key)
    return rp_id_hash + bytes([flags]) + sign_count + att_cred_data


def _build_plain_authenticator_data() -> bytes:
    """authenticatorData for an assertion (no attested credential data)."""
    rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
    flags = 0x05  # UP | UV
    sign_count = struct.pack(">I", 1)
    return rp_id_hash + bytes([flags]) + sign_count


class SimulatedAuthenticator:
    """A stand-in for the browser/native WebAuthn backend."""

    def __init__(self):
        self.sk = SigningKey.generate(curve=NIST256p)
        self.vk = self.sk.get_verifying_key()
        self.credential_id = os.urandom(32)

    def make_credential(self, rp_id, user_name, hint=""):
        auth_data = _build_attested_authenticator_data(self.vk, self.credential_id)
        return {
            "credential_id": list(self.credential_id),
            "authenticator_data": list(auth_data),
            "transport": "internal",
            "aaguid": "00000000-0000-0000-0000-000000000000",
        }

    def get_assertion(self, rp_id, credential_id, challenge, hint=""):
        auth_data = _build_plain_authenticator_data()
        # The browser signs over a real clientDataJSON, not the raw challenge.
        challenge_b64 = base64.urlsafe_b64encode(bytes(challenge)).rstrip(b"=").decode()
        client_data_json = json.dumps({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": "http://localhost:8580",
            "crossOrigin": False,
        }, separators=(",", ":")).encode()
        client_data_hash = hashlib.sha256(client_data_json).digest()
        # Real platform authenticators (Windows Hello, FIDO2 keys) use
        # deterministic ECDSA (RFC 6979) and a stable signCount, so the
        # signature is identical for a fixed challenge.  The library relies on
        # that stability to recover the same public key every time, so the test
        # authenticator must behave the same way.
        signature = self.sk.sign_deterministic(auth_data + client_data_hash,
                                                hashfunc=hashlib.sha256,
                                                sigencode=sigencode_der)
        return {
            "signature": list(signature),
            "authenticator_data": list(auth_data),
            "client_data_hash": list(client_data_hash),
            "credential_id": list(bytes(credential_id)),
        }


class TestBrowserRoundTrip(unittest.TestCase):
    def setUp(self):
        self.auth = SimulatedAuthenticator()
        self._orig = core._backend
        # Patch only the two functions core.py calls into.
        core._backend.make_credential = self.auth.make_credential
        core._backend.get_assertion = self.auth.get_assertion

        self.tmpdir = tempfile.mkdtemp()
        core.DATA_DIR = os.path.join(self.tmpdir, "data")
        core.CREDENTIAL_FILE = os.path.join(core.DATA_DIR, "credential_id.txt")

    def test_master_key_is_stable_across_assertions(self):
        core.init_credential("tester", hint="client-device")
        k1 = core.get_master_key()
        k2 = core.get_master_key()
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)

    def test_encrypt_then_load_roundtrip(self):
        core.init_credential("tester", hint="client-device")

        env_path = os.path.join(self.tmpdir, ".env")
        with open(env_path, "w") as f:
            f.write("# a comment\n")
            f.write("DATABASE_URL=postgres://user:pw@localhost/db\n")
            f.write("API_KEY=super-secret-123\n")

        core.encrypt_file(env_path)

        with open(env_path) as f:
            encrypted = f.read()
        self.assertIn("ENC:", encrypted)
        self.assertNotIn("super-secret-123", encrypted)
        self.assertIn("recovery info", encrypted)

        os.environ.pop("DATABASE_URL", None)
        os.environ.pop("API_KEY", None)
        core.load_dotenv(env_path)

        self.assertEqual(os.environ["DATABASE_URL"], "postgres://user:pw@localhost/db")
        self.assertEqual(os.environ["API_KEY"], "super-secret-123")


if __name__ == "__main__":
    unittest.main()
