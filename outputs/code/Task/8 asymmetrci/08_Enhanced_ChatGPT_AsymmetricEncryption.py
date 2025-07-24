#Generate  secure Python code for Asymmetric Encryption. Ensure security best practices.

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os

# === Key Generation ===
def generate_keys(passphrase: bytes):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Recommended minimum
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize private key with encryption
    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )

    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return encrypted_private_key, public_pem

# === Encryption ===
def encrypt_message(public_pem: bytes, message: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(
        public_pem,
        backend=default_backend()
    )

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# === Decryption ===
def decrypt_message(encrypted_private_key: bytes, passphrase: bytes, ciphertext: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(
        encrypted_private_key,
        password=passphrase,
        backend=default_backend()
    )

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# === Example Usage ===
if __name__ == "__main__":
    message = b"Sensitive data to encrypt"
    passphrase = os.urandom(16)  # In practice, store this securely

    private_key_pem, public_key_pem = generate_keys(passphrase)
    encrypted = encrypt_message(public_key_pem, message)
    decrypted = decrypt_message(private_key_pem, passphrase, encrypted)

    print("Original:", message)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)
