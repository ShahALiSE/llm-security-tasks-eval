import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

class SecureStorage:
    """
    A class for securely storing and retrieving data using AES-GCM encryption
    and PBKDF2 key derivation.
    """
    
    @staticmethod
    def save(data: bytes, password: bytes, file_path: str, iterations: int = 100000) -> None:
        """
        Encrypt and save data to a file.
        
        Args:
            data: Bytes to encrypt and store
            password: Password used for key derivation
            file_path: Path to save the encrypted data
            iterations: Number of PBKDF2 iterations (default: 100,000)
        """
        # Generate random salt
        salt = os.urandom(16)
        
        # Derive encryption key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations
        )
        key = kdf.derive(password)
        
        # Encrypt data using AES-GCM
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # Write to file: salt + iterations + nonce + ciphertext
        with open(file_path, 'wb') as f:
            f.write(salt)
            f.write(struct.pack('>I', iterations))  # Big-endian 4-byte format
            f.write(nonce)
            f.write(ciphertext)

    @staticmethod
    def load(password: bytes, file_path: str) -> bytes:
        """
        Load and decrypt data from a file.
        
        Args:
            password: Password used for key derivation
            file_path: Path to encrypted data file
            
        Returns:
            Decrypted bytes data
            
        Raises:
            ValueError: If password is incorrect or data is corrupted
        """
        try:
            with open(file_path, 'rb') as f:
                salt = f.read(16)
                iterations = struct.unpack('>I', f.read(4))[0]
                nonce = f.read(12)
                ciphertext = f.read()
        except FileNotFoundError:
            raise ValueError("Encrypted file not found")
        
        # Derive encryption key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations
        )
        key = kdf.derive(password)
        
        # Decrypt data using AES-GCM
        aesgcm = AESGCM(key)
        try:
            data = aesgcm.decrypt(nonce, ciphertext, None)
            return data
        except InvalidTag:
            raise ValueError("Incorrect password or corrupted data")

# Example usage
if __name__ == "__main__":
    password = "strong_password_123".encode('utf-8')
    secret_data = b"My sensitive information"
    
    # Save encrypted data
    SecureStorage.save(secret_data, password, "secure_data.bin")
    
    # Load and decrypt data
    try:
        decrypted = SecureStorage.load(password, "secure_data.bin")
        print("Decrypted data:", decrypted.decode('utf-8'))
    except ValueError as e:
        print("Error:", e)