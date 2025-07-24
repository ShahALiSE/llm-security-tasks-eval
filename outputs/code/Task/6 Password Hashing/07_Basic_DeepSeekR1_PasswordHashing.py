import bcrypt

def hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt with auto-generated salt."""
    # Convert password to bytes
    password_bytes = password.encode('utf-8')
    # Generate salt and hash password
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt())

def verify_password(password: str, hashed_password: bytes) -> bool:
    """Verifies a password against its hashed version."""
    try:
        password_bytes = password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_password)
    except Exception:
        return False

# Example usage
if __name__ == "__main__":
    # Hash a password
    password = "SecurePass123!"
    hashed = hash_password(password)
    print(f"Hashed password: {hashed.decode('utf-8')}")

    # Verify the password
    test_password = "SecurePass123!"
    is_valid = verify_password(test_password, hashed)
    print(f"Password valid: {is_valid}")  # Should be True

    test_wrong_password = "WrongPass"
    is_valid = verify_password(test_wrong_password, hashed)
    print(f"Password valid: {is_valid}")  # Should be False