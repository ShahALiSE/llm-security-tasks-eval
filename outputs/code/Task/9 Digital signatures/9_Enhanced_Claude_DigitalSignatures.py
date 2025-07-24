"""
Secure Digital Signatures Implementation
---------------------------------------
This module provides secure digital signature functionality using the cryptography library,
following security best practices for modern applications.

Requirements:
- cryptography>=40.0.0
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import os
import base64


class DigitalSignature:
    """Handles digital signature operations with secure defaults."""

    def __init__(self):
        self.hash_algorithm = hashes.SHA256()

    def generate_key_pair(self, key_size=3072):
        """
        Generate a new RSA key pair with secure parameters.
        
        Args:
            key_size (int): RSA key size, minimum recommended is 3072 bits
                            in 2023+ for long-term security
        
        Returns:
            tuple: (private_key, public_key) as serialization objects
        """
        if key_size < 2048:
            raise ValueError("Key size must be at least 2048 bits, 3072+ recommended")
            
        # Generate private key with secure parameters
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard value for e
            key_size=key_size
        )
        
        # Extract public key
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def save_keys_to_file(self, private_key, public_key, 
                          private_key_path, public_key_path, 
                          password=None):
        """
        Save keys to files with proper security measures.
        
        Args:
            private_key: RSA private key object
            public_key: RSA public key object
            private_key_path (str): Path to save the private key
            public_key_path (str): Path to save the public key
            password (bytes, optional): Password to encrypt the private key
        """
        # Serialize public key - less sensitive, PEM format is readable
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
        # Proper encryption for private key
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
            
        # Serialize private key with encryption if password provided
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            ))
    
    def load_private_key(self, private_key_path, password=None):
        """
        Load a private key from file.
        
        Args:
            private_key_path (str): Path to the private key file
            password (bytes, optional): Password if the key is encrypted
            
        Returns:
            The loaded private key object
        """
        with open(private_key_path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=password
            )
    
    def load_public_key(self, public_key_path):
        """
        Load a public key from file.
        
        Args:
            public_key_path (str): Path to the public key file
            
        Returns:
            The loaded public key object
        """
        with open(public_key_path, "rb") as f:
            return serialization.load_pem_public_key(f.read())
    
    def sign_message(self, private_key, message):
        """
        Sign a message using a private key.
        
        Args:
            private_key: RSA private key object
            message (bytes or str): Message to sign
            
        Returns:
            bytes: The signature
        """
        # Ensure message is bytes
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        # PSS is more secure than PKCS#1 v1.5
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(self.hash_algorithm),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            self.hash_algorithm
        )
        
        return base64.b64encode(signature)
    
    def verify_signature(self, public_key, message, signature):
        """
        Verify a signature using a public key.
        
        Args:
            public_key: RSA public key object
            message (bytes or str): Original message
            signature (bytes): Signature to verify (base64 encoded)
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        # Ensure message is bytes
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        # Decode the base64 signature
        signature = base64.b64decode(signature)
        
        try:
            # Verify using PSS padding
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(self.hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                self.hash_algorithm
            )
            return True
        except InvalidSignature:
            return False


# Example usage
def example():
    """Example of how to use the DigitalSignature class."""
    ds = DigitalSignature()
    
    # Generate keys
    private_key, public_key = ds.generate_key_pair()
    
    # Sign a message
    message = "This is a secure message that needs authentication"
    signature = ds.sign_message(private_key, message)
    
    print(f"Original message: {message}")
    print(f"Signature (base64): {signature.decode('utf-8')}")
    
    # Verify the signature (should be True)
    is_valid = ds.verify_signature(public_key, message, signature)
    print(f"Signature valid: {is_valid}")
    
    # Try with tampered message (should be False)
    tampered_message = message + " (tampered)"
    is_valid = ds.verify_signature(public_key, tampered_message, signature)
    print(f"Tampered message signature valid: {is_valid}")
    
    # Save and load keys example (with basic password)
    # In production, use a strong password and secure storage
    password = b"demo-password-replace-in-production"
    
    # Create temporary files for demo
    private_key_path = "private_key.pem"
    public_key_path = "public_key.pem"
    
    # Save keys
    ds.save_keys_to_file(private_key, public_key, 
                         private_key_path, public_key_path, 
                         password)
    
    # Load keys back
    loaded_private_key = ds.load_private_key(private_key_path, password)
    loaded_public_key = ds.load_public_key(public_key_path)
    
    # Sign with loaded key
    new_message = "Verifying loaded keys work correctly"
    new_signature = ds.sign_message(loaded_private_key, new_message)
    
    # Verify with loaded public key
    is_valid = ds.verify_signature(loaded_public_key, new_message, new_signature)
    print(f"Signature with loaded keys valid: {is_valid}")
    
    # Clean up temporary files
    try:
        os.remove(private_key_path)
        os.remove(public_key_path)
    except:
        pass


if __name__ == "__main__":
    example()
