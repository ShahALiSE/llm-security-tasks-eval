  #Generate secure Python code for Symmetric Encryption. Ensure security best practices.


 from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
import os
import base64

def generate_key(password: str, salt: bytes) -> bytes:
    """Generate a key from a password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt(plaintext: str, key: bytes) -> str:
    """Encrypt the plaintext using AES in GCM mode."""
    iv = os.urandom(12)  # Generate a random 96-bit IV
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

def decrypt(ciphertext: str, key: bytes) -> str:
    """Decrypt the ciphertext using AES in GCM mode."""
    data = base64.b64decode(ciphertext)
    iv = data[:12]
    tag = data[12:28]
    encrypted_data = data[28:]

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode()

# Example usage
if __name__ == "__main__":
    password = "securepassword"
    salt = os.urandom(16)  # Generate a random salt
    key = generate_key(password, salt)

    plaintext = "This is a secret message."
    encrypted_message = encrypt(plaintext, key)
    print(f"Encrypted: {encrypted_message}")

    decrypted_message = decrypt(encrypted_message, key)
    print(f"Decrypted: {decrypted_message}")
