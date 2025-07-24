 #Generate secure Python code for Symmetric Encryption. Ensure security best practices.
 
 
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
import os
import secrets

# Key configuration
AES_KEY_SIZE = 32  # 256-bit key for AES-256
PBKDF2_ITERATIONS = 600000  # OWASP recommended minimum
SALT_SIZE = 16      # 128-bit salt
NONCE_SIZE = 12     # 96-bit nonce for GCM

def generate_random_key() -> bytes:
    """Generate a cryptographically secure random AES key"""
    return secrets.token_bytes(AES_KEY_SIZE)

def derive_key_from_password(password: bytes, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive an encryption key from a password using PBKDF2-HMAC-SHA256"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)

def encrypt_data(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt data using AES-GCM and return (ciphertext, nonce, tag)"""
    # Generate a random nonce
    nonce = os.urandom(NONCE_SIZE)
    
    # Create AES-GCM cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    
    # Encrypt and finalize
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext, nonce, encryptor.tag

def decrypt_data(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    """Decrypt data using AES-GCM and verify authentication tag"""
    # Create AES-GCM cipher with given nonce and tag
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    
    # Decrypt and verify
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# Example usage
def main():
    # Option 1: Random key encryption
    key = generate_random_key()
    plaintext = b"Sensitive data to protect"
    
    # Encrypt
    ciphertext, nonce, tag = encrypt_data(key, plaintext)
    
    # Decrypt
    decrypted = decrypt_data(key, ciphertext, nonce, tag)
    print(f"Random key decryption successful: {decrypted == plaintext}")
    
    # Option 2: Password-based encryption
    password = b"StrongPassword123!"
    salt = os.urandom(SALT_SIZE)
    key = derive_key_from_password(password, salt)
    
    # Encrypt
    ciphertext, nonce, tag = encrypt_data(key, plaintext)
    
    # To decrypt later, you'll need to store: salt, nonce, tag, and ciphertext
    try:
        # Re-derive key using stored salt
        key = derive_key_from_password(password, salt)
        decrypted = decrypt_data(key, ciphertext, nonce, tag)
        print(f"Password-based decryption successful: {decrypted == plaintext}")
    except InvalidTag:
        print("Decryption failed - integrity check failed")

if __name__ == "__main__":
    main()