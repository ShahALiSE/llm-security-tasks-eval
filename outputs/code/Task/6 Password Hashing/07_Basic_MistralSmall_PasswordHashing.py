import os
import hashlib
import base64

def hash_password(password):
    """Hash a password for storing."""
    algorithm = 'pbkdf2_sha256'
    iterations = 100000
    salt_size = 16  # bytes
    salt = os.urandom(salt_size)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    hashed_b64 = base64.b64encode(hashed).decode('utf-8')
    return f"{algorithm}:{iterations}:{salt_b64}:{hashed_b64}"

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user."""
    try:
        algorithm, iterations_str, salt_b64, hashed_b64 = stored_password.split(':')
        iterations = int(iterations_str)
        salt = base64.b64decode(salt_b64.encode('utf-8'))
        stored_hash = base64.b64decode(hashed_b64.encode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        return False

    if algorithm != 'pbkdf2_sha256':
        return False

    try:
        hashed = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, iterations)
    except:
        return False

    if len(hashed) != len(stored_hash):
        return False
    result = 0
    for x, y in zip(hashed, stored_hash):
        result |= x ^ y
    return result == 0

# Example usage
if __name__ == '__main__':
    password = "my_secure_password"
    hashed_password = hash_password(password)
    print("Hashed password:", hashed_password)
    print("Verification with correct password:", verify_password(hashed_password, password))
    print("Verification with wrong password:", verify_password(hashed_password, "wrong_password"))
