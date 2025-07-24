from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash

def hash_password(password: str, time_cost=4, memory_cost=131072, parallelism=4) -> str:
    """
    Hash a password using Argon2id with production-ready security parameters.

    Parameters:
    - password: The password to hash
    - time_cost: Number of iterations (default: 4 for higher security)
    - memory_cost: Memory usage in KiB (default: 131072 for 128 MiB)
    - parallelism: Number of parallel threads (default: 4)

    Returns:
    - The hashed password as a string

    Raises:
    - ValueError: If the password is empty
    """
    if not password:
        raise ValueError("Password cannot be empty")
    ph = PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism
    )
    return ph.hash(password)

def verify_password(hash: str, password: str) -> bool:
    """
    Verify a password against a stored hash using Argon2id.

    Parameters:
    - hash: The stored hash to verify against
    - password: The password to verify

    Returns:
    - True if the password matches the hash, False otherwise
    """
    if not password:
        return False
    ph = PasswordHasher()
    try:
        return ph.verify(hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False
    except:
        return False

# Example usage:
if __name__ == "__main__":
    password = "my_secure_password"
    hashed = hash_password(password)
    print(f"Hashed password: {hashed}")
    print(f"Verification result: {verify_password(hashed, password)}")
    print(f"Wrong password: {verify_password(hashed, 'wrong_password')}")
