import os
import json
import base64
import hashlib
import struct
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from ecdsa import NIST256p, VerifyingKey
from ecdsa.util import sigdecode_der
import cbor2
from . import _backend

# Configuration
# RP_ID is backend-dependent: the native Windows module uses a custom domain,
# while the browser backend must use "localhost" (the page's effective origin).
RP_ID = _backend.RP_ID


def _default_data_dir() -> str:
    """Per-user data directory, following each platform's convention."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    else:
        # XDG Base Directory spec, with the documented fallback.
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(
            os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "dotenv-webauthn")


DATA_DIR = _default_data_dir()
CREDENTIAL_FILE = os.path.join(DATA_DIR, "credential_id.txt")
AAGUID_DB_URL = "https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/aaguid.json"

def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)

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

def _pubkey_tag(pubkey: bytes) -> str:
    """Disambiguation tag for a public key, stored to pick the right candidate.

    It is SHA256(SHA256(pubkey)) — deliberately *different* from the master key
    derivation (which is SHA256(pubkey)).  This domain separation is critical:
    storing SHA256(pubkey) would be storing the encryption key itself.  The
    double hash is preimage-resistant, so the tag reveals neither the public key
    nor the master key, yet it uniquely identifies the correct recovery
    candidate from a single assertion — even when the authenticator produces
    randomized (non-deterministic) signatures.
    """
    return base64.b64encode(hashlib.sha256(hashlib.sha256(pubkey).digest()).digest()).decode()


def _recover_public_key(signature: bytes, authenticator_data: bytes, client_data_hash: bytes,
                        y_parity: int, pubkey_tag: str = "") -> bytes:
    """Recover the ECDSA public key from a WebAuthn assertion signature.

    Returns the uncompressed public key bytes (65 bytes: 0x04 || x || y).

    A single assertion yields ~2 recovery candidates (the real key plus a decoy
    that is valid only for *this* signature).  Selection:
      * if ``pubkey_tag`` is provided, pick the candidate whose tag matches —
        robust even for randomized signatures (works in a single tap); else
      * fall back to ``y_parity`` (legacy: only reliable when the authenticator
        signs deterministically, e.g. Windows Hello).

    ``client_data_hash`` is the exact 32-byte hash that the authenticator
    signed.  It is provided by the backend because it differs per platform:
    ``SHA256(challenge)`` for the native Windows API, ``SHA256(clientDataJSON)``
    for the browser backend.
    """
    signed_data = authenticator_data + client_data_hash
    candidates = VerifyingKey.from_public_key_recovery(
        signature, signed_data, NIST256p,
        hashfunc=hashlib.sha256, sigdecode=sigdecode_der
    )
    if pubkey_tag:
        for candidate in candidates:
            uncompressed = candidate.to_string("uncompressed")
            if _pubkey_tag(uncompressed) == pubkey_tag:
                return uncompressed
        raise ValueError("No recovery candidate matches the stored public-key tag "
                         "(wrong credential or corrupted metadata).")
    for candidate in candidates:
        if candidate.pubkey.point.y() % 2 == y_parity:
            return candidate.to_string("uncompressed")
    raise ValueError("No candidate matches the expected y_parity")

def init_credential(user_name: str = "default_user", hint: str = ""):
    ensure_data_dir()
    if os.path.exists(CREDENTIAL_FILE):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        backup_name = f"credential_id_{timestamp}.txt"
        backup_path = os.path.join(DATA_DIR, backup_name)
        os.rename(CREDENTIAL_FILE, backup_path)
        print(f"WARNING: Existing credential backed up to {backup_path}")

    # Create credential — returns credential_id + authenticatorData (contains public key)
    result = _backend.make_credential(RP_ID, user_name, hint)
    credential_id = bytes(result["credential_id"])
    auth_data = bytes(result["authenticator_data"])
    transport = result.get("transport", "unknown")
    aaguid = result.get("aaguid", "")

    # Extract public key from authenticatorData. We keep y_parity for backward
    # compatibility, and derive the disambiguation tag used at decryption time.
    x, y = _parse_public_key_from_authenticator_data(auth_data)
    y_parity = y[-1] & 1  # last byte's LSB = parity of y coordinate
    uncompressed_pubkey = b'\x04' + x + y  # same encoding as VerifyingKey.to_string("uncompressed")
    pubkey_tag = _pubkey_tag(uncompressed_pubkey)

    # Map hint back to device name for readability
    device_map = {"client-device": "local", "hybrid": "phone", "security-key": "usb"}
    device = device_map.get(hint, hint or "any")

    # Store all metadata as key=value
    encoded = base64.b64encode(credential_id).decode('utf-8')
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(CREDENTIAL_FILE, "w") as f:
        f.write(f'CREDENTIAL_ID="{encoded}"\n')
        f.write(f'Y_PARITY={y_parity}\n')
        f.write(f'PUBKEY_TAG="{pubkey_tag}"\n')
        f.write(f'RP_ID="{RP_ID}"\n')
        f.write(f'USER_NAME="{user_name}"\n')
        f.write(f'DEVICE="{device}"\n')
        f.write(f'TRANSPORT="{transport}"\n')
        f.write(f'AAGUID="{aaguid}"\n')
        f.write(f'CREATED_AT="{now}"\n')
    print(f"Root credential initialized and saved to {CREDENTIAL_FILE}")

def _read_credential_file():
    """Read credential metadata from credential file.

    Supports both new key=value format and legacy 2-line format.
    Returns dict with at least 'credential_id' (bytes) and 'y_parity' (int).
    """
    if not os.path.exists(CREDENTIAL_FILE):
        raise FileNotFoundError("Root credential not found. Run 'init' first.")
    with open(CREDENTIAL_FILE, "r") as f:
        content = f.read().strip()

    lines = content.split('\n')

    # Detect format: new format has '=' with key names, old format is raw base64 on line 1
    if '=' in lines[0]:
        # New key=value format
        meta = {}
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                # Strip surrounding quotes
                value = value.strip().strip('"')
                meta[key.strip()] = value
        credential_id = base64.b64decode(meta['CREDENTIAL_ID'])
        y_parity = int(meta.get('Y_PARITY', '0'))
        return {
            'credential_id': credential_id,
            'y_parity': y_parity,
            'pubkey_tag': meta.get('PUBKEY_TAG', ''),
            'rp_id': meta.get('RP_ID', RP_ID),
            'user_name': meta.get('USER_NAME', 'unknown'),
            'device': meta.get('DEVICE', 'unknown'),
            'transport': meta.get('TRANSPORT', 'unknown'),
            'aaguid': meta.get('AAGUID', ''),
            'created_at': meta.get('CREATED_AT', ''),
        }
    else:
        # Legacy 2-line format: line 1 = base64 credential_id, line 2 = y_parity
        credential_id = base64.b64decode(lines[0])
        y_parity = int(lines[1]) if len(lines) > 1 else 0
        return {
            'credential_id': credential_id,
            'y_parity': y_parity,
            'pubkey_tag': '',
            'rp_id': RP_ID,
            'user_name': 'unknown',
            'device': 'unknown',
            'transport': 'unknown',
            'aaguid': '',
            'created_at': '',
        }

def get_master_key(pubkey_tag: str = "") -> bytes:
    meta = _read_credential_file()
    credential_id = meta['credential_id']
    y_parity = meta['y_parity']
    # Prefer a tag supplied by the caller (e.g. from the .env recovery header,
    # which makes the vault self-sufficient), otherwise use the one stored
    # alongside the credential.
    tag = pubkey_tag or meta.get('pubkey_tag', '')

    # Get assertion — user must authenticate (biometric/PIN)
    result = _backend.get_assertion(RP_ID, list(credential_id), list(FIXED_CHALLENGE))
    signature = bytes(result["signature"])
    auth_data = bytes(result["authenticator_data"])
    client_data_hash = bytes(result["client_data_hash"])

    # Recover public key from signature (never stored on disk)
    pubkey = _recover_public_key(signature, auth_data, client_data_hash, y_parity, tag)
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

def _read_header_pubkey_tag(lines) -> str:
    """Extract PUBKEY_TAG from a vault's recovery header, if present.

    Lets a vault be decrypted from its own header even if the local credential
    file lacks the tag (e.g. it predates this feature, or was moved machines).
    """
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('#') and 'PUBKEY_TAG=' in stripped:
            value = stripped.split('PUBKEY_TAG=', 1)[1].strip().strip('"')
            return value
    return ""


def load_dotenv(dotenv_path: str = ".env"):
    if not os.path.exists(dotenv_path):
        return

    # Check if we need to decrypt anything first
    needs_decryption = False
    lines = []
    with open(dotenv_path, "r") as f:
        lines = f.readlines()
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('#') and "=" in stripped:
                _, value = stripped.split("=", 1)
                if value.startswith("ENC:"):
                    needs_decryption = True
                    break

    if not needs_decryption:
        # Standard load
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('#') and "=" in stripped:
                key, value = stripped.split("=", 1)
                os.environ[key] = value
        return

    # Perform decryption — prefer the tag carried in the file's own header.
    master_key = get_master_key(pubkey_tag=_read_header_pubkey_tag(lines))
    vault_key = get_vault_key(dotenv_path, master_key)

    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and "=" in stripped:
            key, value = stripped.split("=", 1)
            if value.startswith("ENC:"):
                try:
                    os.environ[key] = decrypt_value(value, vault_key)
                except Exception as e:
                    import traceback
                    print(f"Failed to decrypt {key}: {e}")
                    traceback.print_exc()
            else:
                os.environ[key] = value

def fetch_aaguid_info(aaguid: str) -> dict:
    """Fetch authenticator info from the passkeydeveloper AAGUID database.

    Returns dict with 'name' and 'icon_light'/'icon_dark' if found, empty dict otherwise.
    """
    if not aaguid:
        return {}
    try:
        import urllib.request
        with urllib.request.urlopen(AAGUID_DB_URL, timeout=10) as resp:
            db = json.loads(resp.read().decode('utf-8'))
        return db.get(aaguid, {})
    except Exception:
        return {}


def get_credential_info() -> dict:
    """Read credential metadata and return a dict with all stored info."""
    return _read_credential_file()


def _build_recovery_header(meta: dict, env_path: str) -> list:
    """Build comment lines with credential recovery information."""
    lines = []
    lines.append("# --- dotenv-webauthn-crypt recovery info ---\n")
    lines.append(f'# CREDENTIAL_ID="{base64.b64encode(meta["credential_id"]).decode()}"\n')
    lines.append(f'# Y_PARITY={meta.get("y_parity", 0)}\n')
    lines.append(f'# PUBKEY_TAG="{meta.get("pubkey_tag", "")}"\n')
    lines.append(f'# RP_ID="{meta.get("rp_id", RP_ID)}"\n')
    lines.append(f'# USER_NAME="{meta.get("user_name", "unknown")}"\n')
    lines.append(f'# DEVICE="{meta.get("device", "unknown")}"\n')
    lines.append(f'# TRANSPORT="{meta.get("transport", "unknown")}"\n')
    lines.append(f'# AAGUID="{meta.get("aaguid", "")}"\n')
    lines.append(f'# CREATED_AT="{meta.get("created_at", "")}"\n')
    lines.append(f'# ENCRYPTED_AT="{datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}"\n')
    lines.append(f'# VAULT_PATH="{os.path.abspath(env_path)}"\n')
    lines.append("# --- end recovery info ---\n")
    return lines


def encrypt_file(dotenv_path: str):
    if not os.path.exists(dotenv_path):
        raise FileNotFoundError(f"{dotenv_path} not found")

    master_key = get_master_key()
    vault_key = get_vault_key(dotenv_path, master_key)

    # Read existing lines, stripping any old recovery header
    data_lines = []
    with open(dotenv_path, "r") as f:
        in_header = False
        for line in f:
            if line.startswith("# --- dotenv-webauthn-crypt recovery info ---"):
                in_header = True
                continue
            if in_header:
                if line.startswith("# --- end recovery info ---"):
                    in_header = False
                continue
            data_lines.append(line)

    # Encrypt values
    new_lines = []
    for line in data_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and "=" in stripped:
            key, value = stripped.split("=", 1)
            if not value.startswith("ENC:"):
                encrypted = encrypt_value(value, vault_key)
                new_lines.append(f"{key}={encrypted}\n")
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    # Build recovery header from credential metadata
    meta = _read_credential_file()
    header = _build_recovery_header(meta, dotenv_path)

    with open(dotenv_path, "w") as f:
        f.writelines(header)
        f.writelines(new_lines)
    print(f"File {dotenv_path} encrypted successfully.")
