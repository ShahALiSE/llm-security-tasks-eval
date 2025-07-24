import argon2
import os
import base64
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# Configure Argon2 parameters (adjust based on your system's performance)
ARGON2_TIME_COST = 2          # Number of iterations (increase for better security)
ARGON2_MEMORY_COST = 102400   # Memory usage in KiB (100 MiB)
ARGON2_PARALLELISM = 8        # Number of parallel threads
ARGON2_HASH_LENGTH = 32       # Hash output length in bytes
ARGON2_SALT_LENGTH = 16       # Salt length in bytes

# Initialize Argon2 PasswordHasher with custom parameters
_ph = argon2.PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LENGTH,
    salt_len=ARGON2_SALT_LENGTH
)

def hash_password(password: str) -> str:
    """
    Securely hash a password using Argon2.
    
    Args:
        password: The plaintext password to hash.
    
    Returns:
        A string containing the hashed password.
    """
    # Generate a random salt and hash the password
    return _ph.hash(password)

def verify_password(hashed_password: str, password: str) -> bool:
    """
    Verify a plaintext password against a stored hash.
    
    Args:
        hashed_password: The hashed password retrieved from storage.
        password: The plaintext password to verify.
    
    Returns:
        True if the password matches, False otherwise.
    
    Raises:
        argon2.exceptions.VerificationError: If the hash format is invalid.
    """
    try:
        # Verify password and automatically handle rehashing if needed
        return _ph.verify(hashed_password, password)
    except VerifyMismatchError:
        # Password does not match
        return False
    except InvalidHashError as e:
        # The hash is corrupted or in an unknown format
        raise argon2.exceptions.VerificationError("Invalid hash format") from e

# Example usage
if __name__ == "__main__":
    # Simulate user registration: Hash a password
    user_password = "MySecurePassword123!"
    hashed = hash_password(user_password)
    print(f"Stored Hash: {hashed}")

    # Simulate login attempt: Verify a password
    test_password = "MySecurePassword123!"
    is_valid = verify_password(hashed, test_password)
    print(f"Password Valid: {is_valid}")  # Expected: True

    test_password = "WrongPassword"
    is_valid = verify_password(hashed, test_password)
    print(f"Password Valid: {is_valid}")  # Expected: False