import json
import os
import re

def calculate_password_strength(password):
    """
    Calculate password strength based on multiple criteria.
    Returns: "weak", "medium", or "strong"
    """
    if not password:
        return "weak"

    # Basic checks
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:,.<>?]', password))
    length = len(password)

    # Calculate score
    score = 0
    if length >= 12: score += 2
    elif length >= 8: score += 1
    if has_upper: score += 1
    if has_lower: score += 1
    if has_digit: score += 1
    if has_special: score += 1

    # Determine strength
    if score >= 5:
        return "strong"
    elif score >= 3:
        return "medium"
    else:
        return "weak"

def show_password_strength(password):
    """Returns strength indicator with appropriate color."""
    strength = calculate_password_strength(password)
    strength_colors = {
        "weak": "#ff3d3d",     # Red
        "medium": "#ffa723",   # Orange
        "strong": "#1f9c1f"    # Green
    }
    strength_text = {
        "weak": "● Weak Password",
        "medium": "● Medium Password",
        "strong": "● Strong Password"
    }
    return (strength_text[strength], strength_colors[strength])

# === Theme Management ===
SETTINGS_FILE = "settings.json"

def load_theme_preference():
    """Load saved theme preference."""
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r") as f:
                settings = json.load(f)
                return settings.get("theme", "dark")
        except:
            return "dark"
    return "dark"

def save_theme_preference(theme):
    """Save theme preference to file."""
    settings = {}
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r") as f:
                settings = json.load(f)
        except:
            pass
    
    settings["theme"] = theme
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f)