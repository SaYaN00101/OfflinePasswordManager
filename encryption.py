# encryption.py
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# === Constants ===
SALT_FILE = "salt.bin"



class SecureString:
    def __init__(self, string):
        self._string = string

    def __del__(self):
        if self._string:
            self._string = '0' * len(self._string)

    def get(self):
        return self._string


# --- Helper Functions ---
def get_or_create_salt():
    """Create or load the salt used for deriving the encryption key."""
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    return salt


def derive_key_from_master(master_password: str):
    """Derive a Fernet key using the master password and stored salt."""
    salt = get_or_create_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


def get_fernet(master_password: str):
    """Return a Fernet instance based on the current master password."""
    key = derive_key_from_master(master_password)
    return Fernet(key)


# --- Encryption/Decryption ---
def encrypt_password(password: str, master_password: str) -> bytes:
    """Encrypt a password using the master password."""
    fernet = get_fernet(master_password)
    return fernet.encrypt(password.encode())


def decrypt_password(encrypted_password: bytes, master_password: str) -> str:
    """Decrypt a password using the master password."""
    fernet = get_fernet(master_password)
    return fernet.decrypt(encrypted_password).decode()
