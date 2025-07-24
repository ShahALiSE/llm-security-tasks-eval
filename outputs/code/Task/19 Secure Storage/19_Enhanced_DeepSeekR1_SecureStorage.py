import os
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

class SecureVault:
    """Secure storage handler using AES-GCM-256 encryption with PBKDF2 key derivation"""
    def __init__(self, password: str):
        self.password = password.encode('utf-8')
        self.kdf_iterations = 600000  # OWASP recommended minimum

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key using PBKDF2-HMAC-SHA256"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.kdf_iterations,
        )
        return kdf.derive(self.password)

    def encrypt_data(self, plaintext: bytes) -> bytes:
        """Encrypt data with fresh cryptographic nonce and salt"""
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(salt)
        
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        
        return salt + nonce + ciphertext

    def decrypt_data(self, encrypted_payload: bytes) -> bytes:
        """Decrypt data with cryptographic integrity verification"""
        if len(encrypted_payload) < 44:  # Minimum valid payload size
            raise ValueError("Invalid encrypted payload")
        
        salt = encrypted_payload[:16]
        nonce = encrypted_payload[16:28]
        ciphertext = encrypted_payload[28:]
        
        key = self._derive_key(salt)
        cipher = AESGCM(key)
        
        try:
            return cipher.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise SecurityError("Authentication failed - potential tampering detected")

def secure_file_operation(input_path: str, output_path: str, password: str, encrypt: bool = True):
    """Handle secure file encryption/decryption operations"""
    vault = SecureVault(password)
    
    try:
        with open(input_path, 'rb') as f:
            file_data = f.read()
            
        processed_data = vault.encrypt_data(file_data) if encrypt \
            else vault.decrypt_data(file_data)
            
        with open(output_path, 'wb') as f:
            f.write(processed_data)
            
    except (ValueError, SecurityError) as e:
        print(f"Critical security error: {str(e)}")
        os.remove(output_path)  # Ensure no partial files remain
        raise

class SecurityError(Exception):
    """Custom security exception for controlled error handling"""

# Example Usage
if __name__ == "__main__":
    secret_data = b"Highly confidential corporate information"
    
    # Get password securely
    passphrase = getpass("Set encryption passphrase: ")
    vault = SecureVault(passphrase)
    
    # Encryption demo
    encrypted = vault.encrypt_data(secret_data)
    print(f"Encrypted payload size: {len(encrypted)} bytes")
    
    # Decryption demo
    try:
        decrypted = vault.decrypt_data(encrypted)
        print(f"Decryption successful: {decrypted.decode()}")
    except SecurityError as e:
        print(f"Decryption blocked: {str(e)}")