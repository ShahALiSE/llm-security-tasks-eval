  #Generate secure Python code for Symmetric Encryption. Ensure security best practices.
  
  
 import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature


def generate_key(password: str, salt: bytes = None) -> tuple:
    """
    Generate a cryptographically secure key from a password using PBKDF2.
    
    Args:
        password: User-provided password
        salt: Optional salt bytes (if None, a random salt is generated)
        
    Returns:
        tuple: (encryption_key, salt)
    """
    if salt is None:
        salt = os.urandom(16)  # 128-bit random salt
    
    # PBKDF2 with SHA-256, 100,000 iterations (adjust based on your security requirements)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
    )
    
    key = kdf.derive(password.encode('utf-8'))
    return key, salt


def encrypt(plaintext: str, key: bytes) -> dict:
    """
    Encrypt data using AES-GCM with authentication.
    
    Args:
        plaintext: Text to encrypt
        key: 32-byte encryption key
        
    Returns:
        dict: Contains all components needed for decryption (iv, ciphertext, tag)
    """
    # Generate a random 96-bit IV (recommended for GCM)
    iv = os.urandom(12)
    
    # Create an encryptor object with AES-GCM
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()
    
    # Convert plaintext to bytes
    plaintext_bytes = plaintext.encode('utf-8')
    
    # Encrypt the data
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    
    # Return a dictionary with everything needed for decryption
    return {
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'tag': base64.b64encode(encryptor.tag).decode('utf-8')
    }


def decrypt(encrypted_data: dict, key: bytes) -> str:
    """
    Decrypt data that was encrypted with AES-GCM.
    
    Args:
        encrypted_data: Dictionary containing iv, ciphertext, and tag
        key: 32-byte encryption key
        
    Returns:
        str: Decrypted plaintext
        
    Raises:
        InvalidSignature: If authentication fails
    """
    # Decode the base64 components
    iv = base64.b64decode(encrypted_data['iv'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    tag = base64.b64decode(encrypted_data['tag'])
    
    # Create a decryptor object with AES-GCM
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag)
    ).decryptor()
    
    # Decrypt the data (this will raise InvalidSignature if authentication fails)
    plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Convert bytes back to string
    return plaintext_bytes.decode('utf-8')


# Example usage
def main():
    # Example password
    password = "my-secure-password"
    message = "This is a secret message."
    
    # Generate a key from the password
    key, salt = generate_key(password)
    
    # Encrypt the message
    encrypted = encrypt(message, key)
    print(f"Encrypted: {encrypted}")
    
    # Save the salt for later decryption
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    print(f"Salt (save this): {salt_b64}")
    
    # Later, to decrypt:
    try:
        # Regenerate the key using the same password and salt
        salt = base64.b64decode(salt_b64)
        key, _ = generate_key(password, salt)
        
        # Decrypt the message
        decrypted = decrypt(encrypted, key)
        print(f"Decrypted: {decrypted}")
    except InvalidSignature:
        print("Decryption failed! Data may have been tampered with.")


if __name__ == "__main__":
    main()