import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from . import _native

# Configuration
RP_ID = "credentials.dotenv-webauthn.com"
DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", ""), "dotenv-webauthn")
CREDENTIAL_FILE = os.path.join(DATA_DIR, "credential.bin")

def ensure_data_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

def init_credential(user_name: str = "default_user"):
    ensure_data_dir()
    credential_id = _native.make_credential(RP_ID, user_name)
    with open(CREDENTIAL_FILE, "wb") as f:
        f.write(bytes(credential_id))
    print(f"Root credential initialized and saved to {CREDENTIAL_FILE}")

def get_root_credential_id() -> bytes:
    if not os.path.exists(CREDENTIAL_FILE):
        raise FileNotFoundError("Root credential not found. Run 'init' first.")
    with open(CREDENTIAL_FILE, "rb") as f:
        return f.read()

def get_master_key() -> bytes:
    credential_id = get_root_credential_id()
    # Challenge can be fixed as per design docs/purpose.md
    challenge = b"dotenv-webauthn-fixed-challenge"
    # Ensure challenge is 32 bytes for consistency with native
    challenge_hash = hashlib.sha256(challenge).digest()
    
    signature = _native.get_assertion(RP_ID, list(credential_id), list(challenge_hash))
    return hashlib.sha256(bytes(signature)).digest()

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
                    print(f"Failed to decrypt {key}: {e}")
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
