import random
import string

def generate_password(length=12, include_symbols=False):
    """
    Generate a password with:
      - Letters (upper & lower)
      - Numbers
      - Optional symbols
    """
    letters = string.ascii_letters   # a-z + A-Z
    digits = string.digits           # 0-9
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    # Always include letters and digits
    characters = letters + digits

    # Add symbols if chosen
    if include_symbols:
        characters += symbols

    # Generate and shuffle
    password = ''.join(random.choice(characters) for _ in range(length))
    password = ''.join(random.sample(password, len(password)))
    return password


# --- Test Section ---
if __name__ == "__main__":
    print("🔹 Standard (letters + numbers):", generate_password(12))
    print("🔹 Strong (letters + numbers + symbols):", generate_password(16, include_symbols=True))
