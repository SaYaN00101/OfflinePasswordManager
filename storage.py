import json
import os
from tkinter import filedialog, messagebox
import zipfile
import session
from encryption import encrypt_password, decrypt_password
import time
from datetime import datetime, timedelta

DATA_FILE = "data.json"
SALT_FILE = "salt.bin"


# ---------- LOAD & SAVE ----------
def load_data():
    """Load password data from the JSON file."""
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r") as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            return {}


def save_data(data):
    """Save dictionary data back into JSON file."""
    with open(DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)


# ---------- CRUD OPERATIONS ----------
def add_entry(website, username, password):
    """Add or update an encrypted password entry."""
    if not session.current_master_password:
        messagebox.showerror("Error", "Master password not loaded.")
        return

    data = load_data()
    encrypted_pw = encrypt_password(password, session.current_master_password).decode()
    data[website] = {"username": username, "password": encrypted_pw}
    save_data(data)


def get_all_sites():
    """Return a list of all saved website names."""
    data = load_data()
    return list(data.keys())


def get_entry(website):
    """Return decrypted username & password for a website."""
    if not session.current_master_password:
        messagebox.showerror("Error", "Master password not loaded.")
        return None

    data = load_data()
    if website not in data:
        return None

    entry = data[website]
    decrypted_pw = decrypt_password(entry["password"].encode(), session.current_master_password)
    return {"username": entry["username"], "password": decrypted_pw}


def delete_entry(website):
    """Delete an entry by website name."""
    data = load_data()
    if website in data:
        del data[website]
        save_data(data)


# ---------- IMPORT / EXPORT ----------
def export_passwords():
    """Export both passwords and salt into one ZIP file."""
    if not os.path.exists(DATA_FILE):
        messagebox.showerror("Error", "No password data found to export.")
        return

    export_path = filedialog.asksaveasfilename(
        defaultextension=".zip",
        filetypes=[("ZIP Archive", "*.zip")],
        title="Export Passwords As"
    )

    if not export_path:
        return

    try:
        with zipfile.ZipFile(export_path, "w") as zipf:
            zipf.write(DATA_FILE)
            if os.path.exists(SALT_FILE):
                zipf.write(SALT_FILE)
        messagebox.showinfo("Success", f"✅ Passwords exported successfully to:\n{export_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to export: {e}")


def import_passwords():
    """Import passwords and salt from ZIP backup."""
    import_path = filedialog.askopenfilename(
        filetypes=[("ZIP Archive", "*.zip")],
        title="Import Password Backup"
    )

    if not import_path:
        return

    try:
        with zipfile.ZipFile(import_path, "r") as zipf:
            zipf.extractall()
        messagebox.showinfo("Success", "✅ Passwords and encryption salt imported successfully!\nPlease restart the app.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to import: {e}")


# ---------- AUTO BACKUP ----------

BACKUP_INTERVAL_DAYS = 1  # change to 7 for weekly backup
BACKUP_FOLDER = "backups"
LAST_BACKUP_FILE = "last_backup.txt"

def auto_backup():
    """Automatically back up data once per interval (daily/weekly)."""
    now = datetime.now()

    # Ensure backup folder exists
    if not os.path.exists(BACKUP_FOLDER):
        os.makedirs(BACKUP_FOLDER)

    # Read last backup time
    if os.path.exists(LAST_BACKUP_FILE):
        with open(LAST_BACKUP_FILE, "r") as f:
            last_backup_str = f.read().strip()
            try:
                last_backup = datetime.fromisoformat(last_backup_str)
            except ValueError:
                last_backup = None
    else:
        last_backup = None

    # Check if backup is due
    if not last_backup or (now - last_backup).days >= BACKUP_INTERVAL_DAYS:
        from storage import export_passwords
        timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
        backup_path = os.path.join(BACKUP_FOLDER, f"backup_{timestamp}.zip")

        try:
            # Export encrypted ZIP backup
            import zipfile
            from encryption import KEY_FILE

            with zipfile.ZipFile(backup_path, "w") as zipf:
                if os.path.exists("data.json"):
                    zipf.write("data.json")
                if os.path.exists("salt.bin"):
                    zipf.write("salt.bin")
                if os.path.exists(KEY_FILE):
                    zipf.write(KEY_FILE)

            # Record timestamp
            with open(LAST_BACKUP_FILE, "w") as f:
                f.write(now.isoformat())

            print(f"✅ Auto backup created: {backup_path}")

        except Exception as e:
            print(f"⚠️ Auto backup failed: {e}")