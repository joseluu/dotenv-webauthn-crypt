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
import re
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
        # Use RANDOMIZED ECDSA (a fresh k each call), the worst case for public
        # key recovery: each signature yields a different decoy candidate.  The
        # PUBKEY_TAG disambiguation must still recover the correct key every
        # time and in a single assertion.  (A real key may also bump signCount;
        # randomizing the signature is a strictly harder test.)
        signature = self.sk.sign(auth_data + client_data_hash,
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
        # With randomized signatures, parity alone would flip ~half the time;
        # the PUBKEY_TAG must keep the master key constant across many taps.
        keys = {core.get_master_key() for _ in range(20)}
        self.assertEqual(len(keys), 1)
        self.assertEqual(len(next(iter(keys))), 32)

    def test_pubkey_tag_is_not_the_master_key(self):
        """The stored tag must be domain-separated from SHA256(pubkey)."""
        core.init_credential("tester", hint="client-device")
        meta = core._read_credential_file()
        master_key = core.get_master_key()
        stored_tag = base64.b64decode(meta["pubkey_tag"])
        self.assertNotEqual(stored_tag, master_key)
        # The tag is the double hash of the same public key the master key uses.
        self.assertEqual(stored_tag, hashlib.sha256(master_key).digest())

    def test_decrypt_from_header_without_credential_file(self):
        """A vault carries its own PUBKEY_TAG and decrypts without Y_PARITY/tag
        in the credential file (e.g. moved to another machine)."""
        core.init_credential("tester", hint="client-device")
        env_path = os.path.join(self.tmpdir, ".env")
        with open(env_path, "w") as f:
            f.write("TOKEN=abc123\n")
        core.encrypt_file(env_path)

        # Wipe the local tag/parity so only the header can disambiguate.
        with open(core.CREDENTIAL_FILE) as f:
            cred = f.read()
        cred = "\n".join(l for l in cred.splitlines()
                         if not l.startswith(("PUBKEY_TAG", "Y_PARITY")))
        with open(core.CREDENTIAL_FILE, "w") as f:
            f.write(cred + "\n")

        os.environ.pop("TOKEN", None)
        core.load_dotenv(env_path)
        self.assertEqual(os.environ["TOKEN"], "abc123")

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


    def test_recovery_header_has_key_metadata(self):
        core.init_credential("tester", hint="security-key", key_name="YubiKey bleue")
        env_path = os.path.join(self.tmpdir, ".env")
        with open(env_path, "w") as f:
            f.write("TOKEN=abc\n")
        core.encrypt_file(env_path)

        with open(env_path) as f:
            hdr = f.read()
        self.assertIn('DEVICE="usb"', hdr)
        self.assertIn('KEY_TYPE="hardware"', hdr)        # usb -> hardware
        self.assertIn('KEY_NAME="YubiKey bleue"', hdr)
        self.assertIn('FIRST_ENCRYPTED_AT="', hdr)

    def test_key_name_optional_omitted_from_header(self):
        core.init_credential("tester", hint="client-device")  # no key_name
        env_path = os.path.join(self.tmpdir, ".env")
        with open(env_path, "w") as f:
            f.write("TOKEN=abc\n")
        core.encrypt_file(env_path)
        with open(env_path) as f:
            hdr = f.read()
        self.assertNotIn("KEY_NAME=", hdr)
        self.assertIn('KEY_TYPE="host"', hdr)            # local -> host

    def test_first_encrypted_at_preserved_on_reencrypt(self):
        core.init_credential("tester", hint="client-device")
        env_path = os.path.join(self.tmpdir, ".env")
        with open(env_path, "w") as f:
            f.write("TOKEN=abc\n")
        core.encrypt_file(env_path)

        # Force an old initial date, then re-encrypt.
        old = "2020-01-01T00:00:00Z"
        with open(env_path) as f:
            content = f.read()
        content = re.sub(r'# FIRST_ENCRYPTED_AT=".*?"',
                         f'# FIRST_ENCRYPTED_AT="{old}"', content)
        with open(env_path, "w") as f:
            f.write(content)

        core.encrypt_file(env_path)
        with open(env_path) as f:
            lines = f.readlines()
        # Initial date survives; last-encrypted date is refreshed.
        self.assertEqual(core._read_header_field(lines, "FIRST_ENCRYPTED_AT"), old)
        self.assertNotEqual(core._read_header_field(lines, "ENCRYPTED_AT"), old)


if __name__ == "__main__":
    unittest.main()
