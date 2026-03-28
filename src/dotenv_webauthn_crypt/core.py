import os
import base64
import hashlib
import struct
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from ecdsa import NIST256p, VerifyingKey
from ecdsa.util import sigdecode_der
import cbor2
from . import _webauthn

# Configuration
RP_ID = "credentials.dotenv-webauthn.com"
DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", ""), "dotenv-webauthn")
CREDENTIAL_FILE = os.path.join(DATA_DIR, "credential_id.txt")

def ensure_data_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

FIXED_CHALLENGE = hashlib.sha256(b"dotenv-webauthn-fixed-challenge-v2").digest()

def _parse_public_key_from_authenticator_data(auth_data: bytes) -> tuple:
    """Parse authenticatorData to extract the COSE public key (x, y) coordinates.

    AuthenticatorData format:
      32 bytes  rpIdHash
       1 byte   flags
       4 bytes  signCount
      If flags & 0x40 (AT flag set):
        16 bytes  AAGUID
         2 bytes  credentialIdLength (big-endian)
         N bytes  credentialId
         M bytes  COSE_Key (CBOR-encoded)
    """
    offset = 32  # rpIdHash
    flags = auth_data[offset]
    offset += 1 + 4  # flags + signCount

    if not (flags & 0x40):
        raise ValueError("No attested credential data in authenticatorData")

    offset += 16  # AAGUID
    cred_id_len = struct.unpack('>H', auth_data[offset:offset + 2])[0]
    offset += 2 + cred_id_len  # credentialIdLength + credentialId

    # Remaining bytes are COSE_Key (CBOR)
    cose_key = cbor2.loads(auth_data[offset:])
    # COSE_Key for P-256: {1: 2, 3: -7, -1: 1, -2: x(32 bytes), -3: y(32 bytes)}
    x = cose_key[-2]  # x coordinate
    y = cose_key[-3]  # y coordinate
    return x, y

def _recover_public_key(signature: bytes, authenticator_data: bytes, challenge: bytes, y_parity: int) -> bytes:
    """Recover the ECDSA public key from a WebAuthn assertion signature.

    Returns the uncompressed public key bytes (65 bytes: 0x04 || x || y).
    Selects the candidate whose y coordinate parity matches y_parity.
    """
    client_data_hash = hashlib.sha256(challenge).digest()
    signed_data = authenticator_data + client_data_hash
    candidates = VerifyingKey.from_public_key_recovery(
        signature, signed_data, NIST256p,
        hashfunc=hashlib.sha256, sigdecode=sigdecode_der
    )
    for candidate in candidates:
        if candidate.pubkey.point.y() % 2 == y_parity:
            return candidate.to_string("uncompressed")
    raise ValueError("No candidate matches the expected y_parity")

def init_credential(user_name: str = "default_user"):
    ensure_data_dir()
    if os.path.exists(CREDENTIAL_FILE):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        backup_name = f"credential_id_{timestamp}.txt"
        backup_path = os.path.join(DATA_DIR, backup_name)
        os.rename(CREDENTIAL_FILE, backup_path)
        print(f"WARNING: Existing credential backed up to {backup_path}")

    # Create credential — returns credential_id + authenticatorData (contains public key)
    result = _webauthn.make_credential(RP_ID, user_name)
    credential_id = bytes(result["credential_id"])
    auth_data = bytes(result["authenticator_data"])

    # Extract public key from authenticatorData to determine y_parity
    x, y = _parse_public_key_from_authenticator_data(auth_data)
    y_parity = y[-1] & 1  # last byte's LSB = parity of y coordinate

    # Store credential_id (base64) and y_parity
    encoded = base64.b64encode(credential_id).decode('utf-8')
    with open(CREDENTIAL_FILE, "w") as f:
        f.write(f"{encoded}\n{y_parity}\n")
    print(f"Root credential initialized and saved to {CREDENTIAL_FILE}")

def _read_credential_file():
    """Read credential_id and y_parity from credential file."""
    if not os.path.exists(CREDENTIAL_FILE):
        raise FileNotFoundError("Root credential not found. Run 'init' first.")
    with open(CREDENTIAL_FILE, "r") as f:
        lines = f.read().strip().split('\n')
    credential_id = base64.b64decode(lines[0])
    y_parity = int(lines[1]) if len(lines) > 1 else 0
    return credential_id, y_parity

def get_master_key() -> bytes:
    credential_id, y_parity = _read_credential_file()

    # Get assertion — user must authenticate (biometric/PIN)
    result = _webauthn.get_assertion(RP_ID, list(credential_id), list(FIXED_CHALLENGE))
    signature = bytes(result["signature"])
    auth_data = bytes(result["authenticator_data"])

    # Recover public key from signature (never stored on disk)
    pubkey = _recover_public_key(signature, auth_data, bytes(FIXED_CHALLENGE), y_parity)
    return hashlib.sha256(pubkey).digest()

def get_vault_key(env_path: str, master_key: bytes) -> bytes:
    vault_id = hashlib.sha256(os.path.abspath(env_path).encode()).digest()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=vault_id,
        info=b"dotenv-webauthn-v1",
        backend=default_backend()
    )
    return hkdf.derive(master_key)

def encrypt_value(plaintext: str, vault_key: bytes) -> str:
    aesgcm = AESGCM(vault_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    # Format: version(1 byte) + nonce(12) + ciphertext(N) + tag(included in ciphertext in cryptography lib)
    # version 0x01
    full_data = b'\x01' + nonce + ciphertext
    return "ENC:" + base64.b64encode(full_data).decode('utf-8')

def decrypt_value(enc_value: str, vault_key: bytes) -> str:
    if not enc_value.startswith("ENC:"):
        return enc_value
    
    data = base64.b64decode(enc_value[4:])
    version = data[0]
    if version != 1:
        raise ValueError(f"Unsupported encryption version: {version}")
    
    nonce = data[1:13]
    ciphertext = data[13:]
    
    aesgcm = AESGCM(vault_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')

def load_dotenv(dotenv_path: str = ".env"):
    if not os.path.exists(dotenv_path):
        return

    # Check if we need to decrypt anything first
    needs_decryption = False
    lines = []
    with open(dotenv_path, "r") as f:
        lines = f.readlines()
        for line in lines:
            if "=" in line:
                _, value = line.strip().split("=", 1)
                if value.startswith("ENC:"):
                    needs_decryption = True
                    break

    if not needs_decryption:
        # Standard load
        for line in lines:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                os.environ[key] = value
        return

    # Perform decryption
    master_key = get_master_key()
    vault_key = get_vault_key(dotenv_path, master_key)

    for line in lines:
        if "=" in line:
            key, value = line.strip().split("=", 1)
            if value.startswith("ENC:"):
                try:
                    os.environ[key] = decrypt_value(value, vault_key)
                except Exception as e:
                    import traceback
                    print(f"Failed to decrypt {key}: {e}")
                    traceback.print_exc()
            else:
                os.environ[key] = value

def encrypt_file(dotenv_path: str):
    if not os.path.exists(dotenv_path):
        raise FileNotFoundError(f"{dotenv_path} not found")

    master_key = get_master_key()
    vault_key = get_vault_key(dotenv_path, master_key)

    new_lines = []
    with open(dotenv_path, "r") as f:
        for line in f:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                if not value.startswith("ENC:"):
                    encrypted = encrypt_value(value, vault_key)
                    new_lines.append(f"{key}={encrypted}\n")
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)

    with open(dotenv_path, "w") as f:
        f.writelines(new_lines)
    print(f"File {dotenv_path} encrypted successfully.")
