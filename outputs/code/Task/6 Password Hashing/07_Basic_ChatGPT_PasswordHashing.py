import bcrypt

# Hash a password
def hash_password(password: str) -> str:
    # Generate salt
    salt = bcrypt.gensalt()
    # Hash the password
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

# Verify a password
def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Example usage
if __name__ == "__main__":
    original_password = "MySecurePassword123!"
    hashed_password = hash_password(original_password)
    print(f"Hashed Password: {hashed_password}")

    # Verification
    is_valid = verify_password("MySecurePassword123!", hashed_password)
    print(f"Password is valid: {is_valid}")
