import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac

# Security parameters
RSA_KEY_SIZE = 4096  # 2048 is minimum recommended today, 4096 for higher security
PUBLIC_EXPONENT = 65537
SALT_SIZE = 16
ITERATIONS = 100000  # For PBKDF2

def generate_key_pair():
    """
    Generate a secure RSA key pair.
    Returns private_key, public_key
    """
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """
    Serialize public key to PEM format
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    """
    Deserialize public key from PEM format
    """
    return serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )

def serialize_private_key(private_key, password=None):
    """
    Serialize private key to PEM format with optional password protection
    """
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password)
    else:
        encryption_algorithm = serialization.NoEncryption()
    
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )

def deserialize_private_key(private_key_bytes, password=None):
    """
    Deserialize private key from PEM format
    """
    return serialization.load_pem_private_key(
        private_key_bytes,
        password=password,
        backend=default_backend()
    )

def encrypt_message(public_key, message):
    """
    Encrypt a message using RSA-OAEP with SHA-256
    """
    # RSA has a maximum message size, so for large messages you'd need to:
    # 1. Generate a symmetric key
    # 2. Encrypt the message with the symmetric key
    # 3. Encrypt the symmetric key with RSA
    # This is implemented in many libraries as "hybrid encryption"
    
    if len(message) > (RSA_KEY_SIZE // 8 - 2 * hashes.SHA256.digest_size - 2):
        raise ValueError("Message too long for RSA encryption")
    
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(private_key, ciphertext):
    """
    Decrypt a message using RSA-OAEP with SHA-256
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def sign_message(private_key, message):
    """
    Sign a message using RSA-PSS with SHA-256
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    """
    Verify a message signature using RSA-PSS with SHA-256
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Example usage
if __name__ == "__main__":
    # Generate keys
    private_key, public_key = generate_key_pair()
    
    # Serialize keys
    pub_key_bytes = serialize_public_key(public_key)
    priv_key_bytes = serialize_private_key(private_key, password=b"strong_password")
    
    # Deserialize keys
    loaded_public_key = deserialize_public_key(pub_key_bytes)
    loaded_private_key = deserialize_private_key(priv_key_bytes, password=b"strong_password")
    
    # Encrypt and decrypt
    message = b"Secret message"
    ciphertext = encrypt_message(loaded_public_key, message)
    decrypted = decrypt_message(loaded_private_key, ciphertext)
    print(f"Decrypted message: {decrypted.decode()}")
    
    # Sign and verify
    signature = sign_message(loaded_private_key, message)
    is_valid = verify_signature(loaded_public_key, message, signature)
    print(f"Signature valid: {is_valid}")