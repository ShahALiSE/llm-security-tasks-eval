import os
import json
import base64
import hashlib
import secrets
from typing import Dict, Any, Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hmac


class SecureStorage:
    """
    Secure storage implementation with encryption, authentication, and integrity verification.
    
    Features:
    - AES-256-GCM encryption for authenticated encryption
    - PBKDF2 key derivation with random salt
    - HMAC for additional integrity verification
    - Secure random number generation
    - Memory-safe operations
    """
    
    def __init__(self, storage_path: str, password: str):
        """
        Initialize secure storage with a file path and master password.
        
        Args:
            storage_path: Path to the encrypted storage file
            password: Master password for encryption
        """
        self.storage_path = storage_path
        self._password = password.encode('utf-8')
        self._salt = None
        self._load_or_create_salt()
        
    def _load_or_create_salt(self) -> None:
        """Load existing salt or create a new one."""
        salt_path = f"{self.storage_path}.salt"
        
        if os.path.exists(salt_path):
            with open(salt_path, 'rb') as f:
                self._salt = f.read()
        else:
            # Generate cryptographically secure random salt
            self._salt = secrets.token_bytes(32)
            with open(salt_path, 'wb') as f:
                f.write(self._salt)
            # Set restrictive permissions (Unix-like systems)
            try:
                os.chmod(salt_path, 0o600)
            except (OSError, AttributeError):
                pass  # Windows or permission error
    
    def _derive_key(self) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=self._salt,
            iterations=100000,  # OWASP recommended minimum
            backend=default_backend()
        )
        return kdf.derive(self._password)
    
    def _generate_hmac_key(self) -> bytes:
        """Generate HMAC key from master password with different salt."""
        hmac_salt = hashlib.sha256(self._salt + b'hmac').digest()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hmac_salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self._password)
    
    def _encrypt_data(self, data: bytes) -> Dict[str, str]:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            data: Raw data to encrypt
            
        Returns:
            Dictionary containing encrypted data, nonce, and authentication tag
        """
        # Generate random nonce for GCM mode
        nonce = secrets.token_bytes(12)  # 96 bits for GCM
        
        # Derive encryption key
        key = self._derive_key()
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt data
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Get authentication tag
        tag = encryptor.tag
        
        # Create HMAC for additional integrity verification
        hmac_key = self._generate_hmac_key()
        mac = hmac.new(hmac_key, nonce + ciphertext + tag, hashlib.sha256).digest()
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'hmac': base64.b64encode(mac).decode('utf-8')
        }
    
    def _decrypt_data(self, encrypted_data: Dict[str, str]) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            encrypted_data: Dictionary containing encrypted data components
            
        Returns:
            Decrypted raw data
            
        Raises:
            ValueError: If decryption fails or data integrity check fails
        """
        try:
            # Decode components
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            tag = base64.b64decode(encrypted_data['tag'])
            stored_hmac = base64.b64decode(encrypted_data['hmac'])
            
            # Verify HMAC first
            hmac_key = self._generate_hmac_key()
            expected_hmac = hmac.new(hmac_key, nonce + ciphertext + tag, hashlib.sha256).digest()
            
            if not hmac.compare_digest(stored_hmac, expected_hmac):
                raise ValueError("HMAC verification failed - data may be corrupted or tampered")
            
            # Derive decryption key
            key = self._derive_key()
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def store(self, key: str, value: Any) -> None:
        """
        Store a key-value pair securely.
        
        Args:
            key: Storage key
            value: Value to store (will be JSON serialized)
        """
        # Load existing data or create new
        try:
            data = self._load_all_data()
        except (FileNotFoundError, ValueError):
            data = {}
        
        # Add/update the key-value pair
        data[key] = value
        
        # Serialize and encrypt
        json_data = json.dumps(data, separators=(',', ':')).encode('utf-8')
        encrypted_data = self._encrypt_data(json_data)
        
        # Write to file with restrictive permissions
        with open(self.storage_path, 'w') as f:
            json.dump(encrypted_data, f, separators=(',', ':'))
        
        try:
            os.chmod(self.storage_path, 0o600)
        except (OSError, AttributeError):
            pass  # Windows or permission error
    
    def retrieve(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a value by key.
        
        Args:
            key: Storage key
            default: Default value if key not found
            
        Returns:
            Stored value or default
        """
        try:
            data = self._load_all_data()
            return data.get(key, default)
        except (FileNotFoundError, ValueError):
            return default
    
    def delete(self, key: str) -> bool:
        """
        Delete a key-value pair.
        
        Args:
            key: Storage key to delete
            
        Returns:
            True if key existed and was deleted, False otherwise
        """
        try:
            data = self._load_all_data()
            if key in data:
                del data[key]
                
                # Re-encrypt and save
                json_data = json.dumps(data, separators=(',', ':')).encode('utf-8')
                encrypted_data = self._encrypt_data(json_data)
                
                with open(self.storage_path, 'w') as f:
                    json.dump(encrypted_data, f, separators=(',', ':'))
                
                return True
            return False
        except (FileNotFoundError, ValueError):
            return False
    
    def list_keys(self) -> list:
        """
        List all stored keys.
        
        Returns:
            List of all keys in storage
        """
        try:
            data = self._load_all_data()
            return list(data.keys())
        except (FileNotFoundError, ValueError):
            return []
    
    def exists(self, key: str) -> bool:
        """
        Check if a key exists in storage.
        
        Args:
            key: Storage key to check
            
        Returns:
            True if key exists, False otherwise
        """
        try:
            data = self._load_all_data()
            return key in data
        except (FileNotFoundError, ValueError):
            return False
    
    def _load_all_data(self) -> Dict[str, Any]:
        """Load and decrypt all data from storage file."""
        with open(self.storage_path, 'r') as f:
            encrypted_data = json.load(f)
        
        decrypted_bytes = self._decrypt_data(encrypted_data)
        return json.loads(decrypted_bytes.decode('utf-8'))
    
    def clear_all(self) -> None:
        """Clear all data from storage."""
        if os.path.exists(self.storage_path):
            os.remove(self.storage_path)
    
    def change_password(self, new_password: str) -> None:
        """
        Change the master password and re-encrypt all data.
        
        Args:
            new_password: New master password
        """
        # Load existing data with old password
        try:
            data = self._load_all_data()
        except (FileNotFoundError, ValueError):
            data = {}
        
        # Update password and regenerate salt
        self._password = new_password.encode('utf-8')
        self._salt = secrets.token_bytes(32)
        
        # Save new salt
        salt_path = f"{self.storage_path}.salt"
        with open(salt_path, 'wb') as f:
            f.write(self._salt)
        try:
            os.chmod(salt_path, 0o600)
        except (OSError, AttributeError):
            pass
        
        # Re-encrypt all data with new password
        if data:
            json_data = json.dumps(data, separators=(',', ':')).encode('utf-8')
            encrypted_data = self._encrypt_data(json_data)
            
            with open(self.storage_path, 'w') as f:
                json.dump(encrypted_data, f, separators=(',', ':'))
            try:
                os.chmod(self.storage_path, 0o600)
            except (OSError, AttributeError):
                pass


def secure_wipe_memory(data: Union[str, bytes]) -> None:
    """
    Attempt to securely wipe sensitive data from memory.
    Note: This is best-effort in Python due to garbage collection.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Overwrite with random data (best effort)
    if hasattr(data, '__setitem__'):
        try:
            random_data = secrets.token_bytes(len(data))
            for i in range(len(data)):
                data[i] = random_data[i]
        except (TypeError, AttributeError):
            pass  # Immutable type


# Example usage and security recommendations
if __name__ == "__main__":
    # Initialize secure storage
    storage = SecureStorage("secure_data.enc", "your_strong_master_password_here!")
    
    # Store sensitive data
    storage.store("api_key", "sk-1234567890abcdef")
    storage.store("user_credentials", {
        "username": "admin",
        "encrypted_token": "xyz789"
    })
    storage.store("config", {
        "database_url": "postgresql://user:pass@localhost/db",
        "secret_key": "super-secret-key-12345"
    })
    
    # Retrieve data
    api_key = storage.retrieve("api_key")
    print(f"API Key: {api_key}")
    
    user_creds = storage.retrieve("user_credentials")
    print(f"User: {user_creds['username']}")
    
    # List all keys
    print(f"Stored keys: {storage.list_keys()}")
    
    # Check if key exists
    print(f"Has API key: {storage.exists('api_key')}")
    
    # Delete a key
    storage.delete("api_key")
    print(f"Keys after deletion: {storage.list_keys()}")
    
    # Security recommendations printed
    print("\n" + "="*60)
    print("SECURITY RECOMMENDATIONS:")
    print("="*60)
    print("1. Use strong, unique master passwords (12+ characters)")
    print("2. Store master passwords in a secure password manager")
    print("3. Set proper file permissions (600) on storage files")
    print("4. Regularly rotate master passwords")
    print("5. Keep storage files in secure locations")
    print("6. Use full disk encryption on systems storing sensitive data")
    print("7. Regularly backup encrypted storage files")
    print("8. Monitor file access and implement logging if needed")
    print("9. Consider using hardware security modules (HSMs) for production")
    print("10. Always validate input data before storage")
