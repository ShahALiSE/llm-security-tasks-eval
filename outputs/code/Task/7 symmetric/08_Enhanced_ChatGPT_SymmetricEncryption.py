  #Generate secure Python code for Symmetric Encryption. Ensure security best practices.


 from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Constants
KEY_SIZE = 32  # AES-256
IV_SIZE = 12   # Recommended for AES-GCM
SALT_SIZE = 16
ITERATIONS = 100_000

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a secure key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(plaintext: str, password: str) -> str:
    """Encrypt the plaintext using a password."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    iv = os.urandom(IV_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), None)
    
    # Encode and combine salt, iv, and ciphertext
    encrypted = base64.b64encode(salt + iv + ciphertext).decode()
    return encrypted

def decrypt(encrypted_data: str, password: str) -> str:
    """Decrypt the ciphertext using a password."""
    data = base64.b64decode(encrypted_data.encode())
    salt = data[:SALT_SIZE]
    iv = data[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = data[SALT_SIZE + IV_SIZE:]
    
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode()

# Example usage
if __name__ == "__main__":
    password = "strongpassword123"
    secret_message = "This is a top secret message."

    encrypted = encrypt(secret_message, password)
    print("Encrypted:", encrypted)

    decrypted = decrypt(encrypted, password)
    print("Decrypted:", decrypted)
