 import os
import base64
from cryptography.fernet import Fernet
from getpass import getpass
from pathlib import Path

# File paths
KEY_FILE = Path.home() / ".secure_storage_key"
DATA_FILE = Path.home() / ".secure_data.enc"

def generate_key(password: str) -> bytes:
    """
    Derive a Fernet-compatible key from a user password.
    """
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes

    salt = b"__STATIC_SALT__CHANGE_ME"  # Replace with securely stored random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def save_secret(secret_name: str, secret_value: str, key: bytes):
    f = Fernet(key)
    encrypted_data = f.encrypt(secret_value.encode())

    # Store each secret as key:value line
    with open(DATA_FILE, "ab") as file:
        file.write(f"{secret_name}:{encrypted_data.decode()}\n".encode())

    os.chmod(DATA_FILE, 0o600)  # Restrict permissions

def get_secret(secret_name: str, key: bytes) -> str | None:
    if not DATA_FILE.exists():
        return None

    f = Fernet(key)

    with open(DATA_FILE, "rb") as file:
        for line in file:
            name, encrypted = line.decode().strip().split(":", 1)
            if name == secret_name:
                decrypted = f.decrypt(encrypted.encode())
                return decrypted.decode()
    return None

def main():
    password = getpass("Enter your master password: ")
    key = generate_key(password)

    while True:
        action = input("Choose [S]ave or [R]etrieve or [Q]uit: ").lower()
        if action == "s":
            name = input("Enter name of secret: ")
            value = getpass("Enter secret value: ")
            save_secret(name, value, key)
            print("Secret saved securely.")
        elif action == "r":
            name = input("Enter name of secret to retrieve: ")
            value = get_secret(name, key)
            if value:
                print(f"Retrieved secret: {value}")
            else:
                print("Secret not found.")
        elif action == "q":
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
