  #Generate Python code for Symmetric Encryption.


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode, b64decode
import os

def generate_key(password: str, salt: bytes) -> bytes:
    """Generate a key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt(plaintext: str, password: str) -> str:
    """Encrypt plaintext using AES."""
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)

    # Pad the plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the plaintext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Combine salt, iv, and ciphertext
    encrypted_message = b64encode(salt + iv + ciphertext).decode('utf-8')
    return encrypted_message

def decrypt(ciphertext: str, password: str) -> str:
    """Decrypt ciphertext using AES."""
    encrypted_message = b64decode(ciphertext.encode('utf-8'))
    salt = encrypted_message[:16]
    iv = encrypted_message[16:32]
    ciphertext = encrypted_message[32:]

    key = generate_key(password, salt)

    # Decrypt the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext.decode('utf-8')

# Example usage
if __name__ == "__main__":
    password = "my_secure_password"
    plaintext = "This is a secret message."

    encrypted_message = encrypt(plaintext, password)
    print(f"Encrypted: {encrypted_message}")

    decrypted_message = decrypt(encrypted_message, password)
    print(f"Decrypted: {decrypted_message}")
