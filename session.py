# session.py
import time



current_master_password = None



# === Session Management ===
current_master_password = None
SESSION_TIMEOUT = 300  # 5 minutes (you can change this)
last_activity = time.time()

def update_activity():
    """Update last user activity timestamp."""
    global last_activity
    last_activity = time.time()

def is_session_expired():
    """Return True if the session has timed out."""
    return time.time() - last_activity > SESSION_TIMEOUT

def logout():
    """Clear session and master password."""
    global current_master_password
    current_master_password = None
    print("🔒 Session ended or logged out.")
