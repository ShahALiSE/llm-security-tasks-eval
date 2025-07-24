 from cryptography.fernet import Fernet
import os
import json

class SecureStorage:
    def __init__(self, key_file='secret.key', storage_file='secure_data.json'):
        self.key_file = key_file
        self.storage_file = storage_file
        self.key = self._load_or_create_key()
        self.fernet = Fernet(self.key)
        self.data = self._load_data()

    def _load_or_create_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            return key

    def _load_data(self):
        if not os.path.exists(self.storage_file):
            return {}
        with open(self.storage_file, 'rb') as f:
            encrypted_data = f.read()
        if not encrypted_data:
            return {}
        decrypted_data = self.fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())

    def _save_data(self):
        encrypted_data = self.fernet.encrypt(json.dumps(self.data).encode())
        with open(self.storage_file, 'wb') as f:
            f.write(encrypted_data)

    def store(self, key, value):
        self.data[key] = value
        self._save_data()

    def retrieve(self, key):
        return self.data.get(key)

    def delete(self, key):
        if key in self.data:
            del self.data[key]
            self._save_data()

# Example usage
if __name__ == '__main__':
    store = SecureStorage()
    store.store('api_key', '12345-ABCDE')
    print("Stored API key.")
    print("Retrieved:", store.retrieve('api_key'))
    store.delete('api_key')
    print("Deleted API key.")
