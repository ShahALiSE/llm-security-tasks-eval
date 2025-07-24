# Required Libraries: pycryptodome
# Install with: pip install pycryptodome

from Crypto.Signature import pss
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.IO import PEM
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import os
import base64

# Key generation parameters
RSA_KEY_LENGTH = 4096  # Minimum recommended RSA key size
PBKDF2_ITERATIONS = 200000  # NIST recommendation for PBKDF2 iterations
SALT_SIZE = 32  # 256-bit salt for PBKDF2

def generate_keys(private_key_file, public_key_file, password=None):
    """
    Generate RSA key pair with secure parameters and store them safely
    - private_key_file: Path to save encrypted private key
    - public_key_file: Path to save public key
    - password: Optional password for private key encryption
    """
    # Generate RSA key pair
    key = RSA.generate(RSA_KEY_LENGTH)
    
    # Export public key
    with open(public_key_file, 'wb') as f:
        f.write(key.publickey().export_key())
    
    # Export encrypted private key
    if password:
        # Generate random salt
        salt = Random.get_random_bytes(SALT_SIZE)
        
        # Derive encryption key using PBKDF2
        encryption_key = PBKDF2(password, salt, 32, count=PBKDF2_ITERATIONS,
                               hmac_hash_module=SHA512)
        
        # Encrypt private key with AES-256-CBC
        iv = Random.get_random_bytes(AES.block_size)
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        encrypted_key = cipher.encrypt(pad(key.export_key(), AES.block_size))
        
        # Save encrypted key with salt and IV
        with open(private_key_file, 'wb') as f:
            f.write(b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n')
            f.write(base64.b64encode(salt + iv + encrypted_key))
            f.write(b'\n-----END ENCRYPTED PRIVATE KEY-----')
    else:
        raise ValueError("Password is required for private key encryption")

def load_private_key(private_key_file, password):
    """
    Load encrypted private key from file
    """
    with open(private_key_file, 'rb') as f:
        encoded_key = f.read()
    
    # Extract base64 encoded data
    header, _, footer = encoded_key.partition(b'\n')
    if b'ENCRYPTED PRIVATE KEY' not in header:
        raise ValueError("Invalid encrypted private key format")
    
    decoded = base64.b64decode(footer.strip())
    salt = decoded[:SALT_SIZE]
    iv = decoded[SALT_SIZE:SALT_SIZE+AES.block_size]
    encrypted_key = decoded[SALT_SIZE+AES.block_size:]
    
    # Derive encryption key
    encryption_key = PBKDF2(password, salt, 32, count=PBKDF2_ITERATIONS,
                          hmac_hash_module=SHA512)
    
    # Decrypt private key
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    decrypted_key = unpad(cipher.decrypt(encrypted_key), AES.block_size)
    
    return RSA.import_key(decrypted_key)

def load_public_key(public_key_file):
    """
    Load public key from file
    """
    with open(public_key_file, 'rb') as f:
        return RSA.import_key(f.read())

def sign_data(data, private_key_file, password):
    """
    Sign data using PSS scheme with SHA-512
    - data: Bytes to sign
    - Returns: Digital signature as bytes
    """
    if not isinstance(data, bytes):
        raise TypeError("Data must be in bytes format")
    
    private_key = load_private_key(private_key_file, password)
    h = SHA512.new(data)
    signature = pss.new(private_key).sign(h)
    return signature

def verify_signature(data, signature, public_key_file):
    """
    Verify PSS signature with SHA-512
    - Returns: True if valid, False otherwise
    """
    if not isinstance(data, bytes) or not isinstance(signature, bytes):
        raise TypeError("Invalid input types")
    
    public_key = load_public_key(public_key_file)
    h = SHA512.new(data)
    verifier = pss.new(public_key)
    
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Example usage
if __name__ == "__main__":
    # Configuration
    PRIVATE_KEY_FILE = "private.pem"
    PUBLIC_KEY_FILE = "public.pem"
    PASSWORD = "StrongPassword123!"  # In practice, get from secure input
    
    # Generate keys (do this once)
    generate_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, PASSWORD)
    
    # Signing example
    message = b"Important document to sign"
    signature = sign_data(message, PRIVATE_KEY_FILE, PASSWORD)
    
    # Verification example
    is_valid = verify_signature(message, signature, PUBLIC_KEY_FILE)
    print(f"Signature valid: {is_valid}")  # Should be True
    
    # Tampered message test
    tampered_message = b"Important document to sign (modified)"
    is_valid_tampered = verify_signature(tampered_message, signature, PUBLIC_KEY_FILE)
    print(f"Tampered signature valid: {is_valid_tampered}")  # Should be False