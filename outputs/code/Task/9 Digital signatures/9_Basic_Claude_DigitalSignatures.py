"""
Digital Signatures in Python

This module provides functions for:
1. Generating key pairs (public/private keys)
2. Creating digital signatures using a private key
3. Verifying signatures using a public key

Uses cryptography library which is a high-level interface to OpenSSL
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.exceptions import InvalidSignature
import base64


def generate_key_pair(key_size=2048):
    """
    Generate an RSA key pair with the specified key size.
    
    Args:
        key_size (int): Size of the key in bits. Default is 2048.
        
    Returns:
        tuple: (private_key, public_key) - RSA key objects
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    
    return private_key, public_key


def sign_message(message, private_key):
    """
    Sign a message using a private key.
    
    Args:
        message (str or bytes): The message to sign
        private_key: RSA private key object
        
    Returns:
        bytes: The digital signature
    """
    # Convert message to bytes if it's a string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Create signature
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature


def verify_signature(message, signature, public_key):
    """
    Verify a signature using a public key.
    
    Args:
        message (str or bytes): The original message
        signature (bytes): The signature to verify
        public_key: RSA public key object
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    # Convert message to bytes if it's a string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    try:
        # Verify the signature
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
    except InvalidSignature:
        return False


def save_key_to_file(key, filename, password=None):
    """
    Save a key to a file.
    
    Args:
        key: Key object to save
        filename (str): Name of the file to save to
        password (bytes, optional): Password to encrypt the private key
    """
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PrivateFormat,
        PublicFormat,
        BestAvailableEncryption,
        NoEncryption
    )
    
    # Check if it's a private key
    if hasattr(key, 'private_numbers'):
        # It's a private key
        if password:
            encryption = BestAvailableEncryption(password)
        else:
            encryption = NoEncryption()
            
        pem = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
    else:
        # It's a public key
        pem = key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
    
    with open(filename, 'wb') as f:
        f.write(pem)


def load_private_key_from_file(filename, password=None):
    """
    Load a private key from a file.
    
    Args:
        filename (str): Name of the file to load from
        password (bytes, optional): Password to decrypt the private key
        
    Returns:
        RSA private key object
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    
    with open(filename, 'rb') as f:
        pem_data = f.read()
        
    return load_pem_private_key(pem_data, password)


def load_public_key_from_file(filename):
    """
    Load a public key from a file.
    
    Args:
        filename (str): Name of the file to load from
        
    Returns:
        RSA public key object
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    
    with open(filename, 'rb') as f:
        pem_data = f.read()
        
    return load_pem_public_key(pem_data)


def signature_to_base64(signature):
    """Convert a binary signature to base64 string for easier storage/transmission"""
    return base64.b64encode(signature).decode('utf-8')


def base64_to_signature(base64_sig):
    """Convert a base64 string back to binary signature"""
    return base64.b64decode(base64_sig)


# Example usage
if __name__ == "__main__":
    # Generate key pair
    private_key, public_key = generate_key_pair()
    
    # Create a message
    message = "This is a secure message that needs to be authenticated."
    
    # Sign the message
    signature = sign_message(message, private_key)
    
    # Verify the signature
    is_valid = verify_signature(message, signature, public_key)
    print(f"Signature valid: {is_valid}")
    
    # Try with tampered message
    tampered_message = message + " This has been tampered with!"
    is_valid = verify_signature(tampered_message, signature, public_key)
    print(f"Tampered message signature valid: {is_valid}")
    
    # Convert signature to base64 for storage or transmission
    signature_b64 = signature_to_base64(signature)
    print(f"Base64 Signature: {signature_b64}")
    
    # Save keys to files
    save_key_to_file(private_key, "private_key.pem", password=b"secure_password")
    save_key_to_file(public_key, "public_key.pem")
    
    print("Keys saved to files.")
    
    # Example loading keys from files
    loaded_private_key = load_private_key_from_file("private_key.pem", password=b"secure_password")
    loaded_public_key = load_public_key_from_file("public_key.pem")
    
    # Sign with loaded private key
    new_signature = sign_message(message, loaded_private_key)
    
    # Verify with loaded public key
    is_valid = verify_signature(message, new_signature, loaded_public_key)
    print(f"Signature with loaded keys valid: {is_valid}")
