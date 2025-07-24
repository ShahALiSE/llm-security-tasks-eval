from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import os
import base64


class AsymmetricCrypto:
    """
    Provides asymmetric encryption/decryption functionality using RSA.
    Implements security best practices including:
    - Appropriate key sizes (minimum 2048 bits)
    - Secure random padding (OAEP)
    - Modern hash functions (SHA-256)
    - Safe key serialization
    """
    
    def __init__(self, key_size=3072):
        """Initialize with a specified key size (default 3072 bits)"""
        if key_size < 2048:
            raise ValueError("Key size must be at least 2048 bits for security")
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_key_pair(self):
        """Generate a new RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard value for e
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()
        return self.public_key, self.private_key
    
    def save_private_key(self, filename, password=None):
        """
        Save the private key to a file, optionally encrypted with a password
        """
        if self.private_key is None:
            raise ValueError("No private key to save. Generate a key pair first.")
        
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        
        with open(filename, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            ))
    
    def save_public_key(self, filename):
        """Save the public key to a file"""
        if self.public_key is None:
            raise ValueError("No public key to save. Generate a key pair first.")
        
        with open(filename, 'wb') as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    def load_private_key(self, filename, password=None):
        """Load a private key from a file, optionally using a password"""
        with open(filename, 'rb') as f:
            key_data = f.read()
        
        if password:
            self.private_key = serialization.load_pem_private_key(
                key_data,
                password=password.encode()
            )
        else:
            self.private_key = serialization.load_pem_private_key(
                key_data,
                password=None
            )
        
        self.public_key = self.private_key.public_key()
        
    def load_public_key(self, filename):
        """Load a public key from a file"""
        with open(filename, 'rb') as f:
            key_data = f.read()
        
        self.public_key = serialization.load_pem_public_key(key_data)
    
    def encrypt(self, message):
        """
        Encrypt a message using the public key
        
        Args:
            message: String or bytes to encrypt
            
        Returns:
            Base64 encoded encrypted message
        """
        if self.public_key is None:
            raise ValueError("No public key available for encryption")
        
        if isinstance(message, str):
            message = message.encode()
        
        if len(message) > (self.key_size // 8 - 66):  # Account for OAEP padding overhead
            raise ValueError(f"Message too long. Maximum length is {self.key_size // 8 - 66} bytes")
            
        ciphertext = self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(ciphertext).decode()
    
    def decrypt(self, encrypted_message):
        """
        Decrypt a message using the private key
        
        Args:
            encrypted_message: Base64 encoded encrypted message
            
        Returns:
            Decrypted message as bytes
        """
        if self.private_key is None:
            raise ValueError("No private key available for decryption")
        
        if isinstance(encrypted_message, str):
            encrypted_message = base64.b64decode(encrypted_message)
            
        plaintext = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext


# Example usage
def main():
    # Create a new asymmetric encryption instance
    crypto = AsymmetricCrypto(key_size=3072)
    
    # Generate a new key pair
    crypto.generate_key_pair()
    
    # Save keys to files (in a real application, store private key securely)
    crypto.save_private_key("private_key.pem", password="secure_password")
    crypto.save_public_key("public_key.pem")
    
    # Encrypt a message
    message = "This is a secret message that needs to be encrypted"
    encrypted = crypto.encrypt(message)
    print(f"Encrypted: {encrypted}")
    
    # Decrypt the message
    decrypted = crypto.decrypt(encrypted)
    print(f"Decrypted: {decrypted.decode()}")
    
    # Example of loading keys from files
    new_crypto = AsymmetricCrypto()
    new_crypto.load_private_key("private_key.pem", password="secure_password")
    
    # Decrypt with loaded key
    decrypted = new_crypto.decrypt(encrypted)
    print(f"Decrypted with loaded key: {decrypted.decode()}")


if __name__ == "__main__":
    main()
