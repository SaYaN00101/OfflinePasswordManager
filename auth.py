#auth.py
import os
import hashlib
from encryption import get_or_create_salt  # to ensure salt exists

MASTER_PASS_FILE = "master.key"
SALT_FILE = "salt.bin"


def hash_password(password):
    """Convert plain password into SHA256 hash."""
    return hashlib.sha256(password.encode()).hexdigest()


def set_master_password_ui(password, confirm):
    """Set master password (called from UI)."""
    if os.path.exists(MASTER_PASS_FILE):
        return "⚠️ Master password already exists."

    if password != confirm:
        return "❌ Passwords do not match."

    # Save hashed master password
    hashed = hash_password(password)
    with open(MASTER_PASS_FILE, "w") as file:
        file.write(hashed)

    # Ensure salt exists for encryption
    get_or_create_salt()

    return "✅ Master password set successfully."


def verify_master_password(input_password):
    """Verify entered password from UI against stored hash."""
    if not os.path.exists(MASTER_PASS_FILE):
        return None  # signal that setup is required

    hashed_input = hash_password(input_password)
    with open(MASTER_PASS_FILE, "r") as file:
        stored_hash = file.read().strip()

    return hashed_input == stored_hash


def reset_master_password():
    """Reset master password if forgotten (deletes all stored data)."""
    confirm = input("⚠️ This will DELETE all stored passwords! Continue? (y/n): ").lower()
    if confirm == "y":
        for file in ["master.key", "data.json", SALT_FILE]:
            if os.path.exists(file):
                os.remove(file)
        print("✅ All data wiped. You can now set a new master password.")
    else:
        print("❎ Cancelled.")


def change_master_password(old_password, new_password, confirm_password):
    """Change master password (if logged in)."""
    if not os.path.exists(MASTER_PASS_FILE):
        return "⚠️ No master password file found."

    hashed_input = hash_password(old_password)
    with open(MASTER_PASS_FILE, "r") as file:
        stored_hash = file.read().strip()

    if hashed_input != stored_hash:
        return "❌ Incorrect current password."

    if new_password != confirm_password:
        return "❌ New passwords do not match."

    # Save new password hash
    new_hash = hash_password(new_password)
    with open(MASTER_PASS_FILE, "w") as file:
        file.write(new_hash)

    # ⚠️ IMPORTANT: keep same salt so old data still decrypts correctly
    if not os.path.exists(SALT_FILE):
        get_or_create_salt()

    return "✅ Master password changed successfully."
