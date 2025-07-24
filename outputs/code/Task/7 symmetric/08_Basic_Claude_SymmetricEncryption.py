  #Generate Python code for Symmetric Encryption.
  
  
from cryptography.fernet import Fernet
import base64
import os


def generate_key():
    """
    Generate a random symmetric encryption key
    """
    return Fernet.generate_key()


def save_key(key, filename="secret.key"):
    """
    Save the encryption key to a file
    """
    with open(filename, "wb") as key_file:
        key_file.write(key)


def load_key(filename="secret.key"):
    """
    Load the encryption key from a file
    """
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Key file '{filename}' not found")
    
    with open(filename, "rb") as key_file:
        return key_file.read()


def encrypt_message(message, key):
    """
    Encrypt a message using the provided key
    
    Args:
        message (str): The message to encrypt
        key (bytes): The encryption key
    
    Returns:
        bytes: The encrypted message
    """
    if isinstance(message, str):
        message = message.encode()
    
    f = Fernet(key)
    return f.encrypt(message)


def decrypt_message(encrypted_message, key):
    """
    Decrypt a message using the provided key
    
    Args:
        encrypted_message (bytes): The encrypted message
        key (bytes): The encryption key
    
    Returns:
        str: The decrypted message
    """
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_message)
    return decrypted.decode()


def main():
    # Example usage
    message = "This is a secret message"
    
    # Generate and save a key
    key = generate_key()
    save_key(key)
    
    # Encrypt the message
    encrypted = encrypt_message(message, key)
    print(f"Encrypted message: {encrypted}")
    
    # Decrypt the message
    decrypted = decrypt_message(encrypted, key)
    print(f"Decrypted message: {decrypted}")


if __name__ == "__main__":
    main()