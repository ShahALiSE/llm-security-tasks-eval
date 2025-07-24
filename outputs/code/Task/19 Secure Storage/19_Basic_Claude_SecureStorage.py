import base64
import os
import json
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecureStorage:
    """A class for securely storing sensitive data using encryption."""
    
    def __init__(self, master_password, storage_file="secure_storage.enc"):
        """
        Initialize the secure storage with a master password.
        
        Args:
            master_password (str): The master password used for encryption/decryption
            storage_file (str): The file where encrypted data will be stored
        """
        self.storage_file = storage_file
        self.key = self._derive_key(master_password)
        self.fernet = Fernet(self.key)
        self.data = self._load_data()
    
    def _derive_key(self, password):
        """Derive an encryption key from the master password using PBKDF2."""
        password_bytes = password.encode('utf-8')
        # Use a fixed salt for simplicity (in production, use a secure, stored salt)
        salt = hashlib.sha256(password_bytes).digest()[:16]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def _load_data(self):
        """Load and decrypt data from the storage file."""
        if not os.path.exists(self.storage_file):
            return {}
        
        try:
            with open(self.storage_file, 'rb') as file:
                encrypted_data = file.read()
                if encrypted_data:
                    decrypted_data = self.fernet.decrypt(encrypted_data)
                    return json.loads(decrypted_data.decode('utf-8'))
                return {}
        except Exception as e:
            print(f"Error loading secure storage: {e}")
            return {}
    
    def _save_data(self):
        """Encrypt and save data to the storage file."""
        try:
            encrypted_data = self.fernet.encrypt(json.dumps(self.data).encode('utf-8'))
            with open(self.storage_file, 'wb') as file:
                file.write(encrypted_data)
            return True
        except Exception as e:
            print(f"Error saving secure storage: {e}")
            return False
    
    def set(self, key, value):
        """
        Store a value securely.
        
        Args:
            key (str): The key to associate with the value
            value: The value to store (must be JSON serializable)
            
        Returns:
            bool: True if successful, False otherwise
        """
        self.data[key] = value
        return self._save_data()
    
    def get(self, key, default=None):
        """
        Retrieve a securely stored value.
        
        Args:
            key (str): The key associated with the value
            default: The value to return if the key doesn't exist
            
        Returns:
            The stored value or the default value
        """
        return self.data.get(key, default)
    
    def delete(self, key):
        """
        Delete a stored value.
        
        Args:
            key (str): The key to delete
            
        Returns:
            bool: True if the key existed and was deleted, False otherwise
        """
        if key in self.data:
            del self.data[key]
            return self._save_data()
        return False
    
    def list_keys(self):
        """
        List all stored keys.
        
        Returns:
            list: A list of all keys in the storage
        """
        return list(self.data.keys())
    
    def change_master_password(self, new_password):
        """
        Change the master password.
        
        Args:
            new_password (str): The new master password
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Store current data
        current_data = self.data
        
        # Update key and cipher
        self.key = self._derive_key(new_password)
        self.fernet = Fernet(self.key)
        
        # Keep the same data but re-encrypt with new key
        self.data = current_data
        return self._save_data()


# Example usage
if __name__ == "__main__":
    # Create a secure storage with a master password
    storage = SecureStorage("my_secret_password")
    
    # Store some sensitive data
    storage.set("api_key", "sk_live_1234567890abcdef")
    storage.set("credentials", {
        "username": "admin",
        "password": "super_secret_123"
    })
    
    # Retrieve data
    api_key = storage.get("api_key")
    credentials = storage.get("credentials")
    
    print(f"API Key: {api_key}")
    print(f"Credentials: {credentials}")
    
    # List all keys
    print(f"All keys: {storage.list_keys()}")
    
    # Delete a key
    storage.delete("api_key")
    print(f"After deletion, keys: {storage.list_keys()}")
    
    # Demonstrate password change
    storage.change_master_password("new_stronger_password")
    print("Password changed successfully, data preserved")
    print(f"Can still access credentials: {storage.get('credentials')}")
