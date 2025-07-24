 #Generate Python code for Symmetric Encryption.
 
 
 from cryptography.fernet import Fernet

def generate_and_save_key(key_file='secret.key'):
    """
    Generates a new encryption key and saves it to a file
    """
    key = Fernet.generate_key()
    with open(key_file, 'wb') as key_file:
        key_file.write(key)
    print(f"Key saved to {key_file.name}")

def load_key(key_file='secret.key'):
    """
    Loads the encryption key from a file
    """
    return open(key_file, 'rb').read()

def encrypt_message(message, key):
    """
    Encrypts a message using the provided key
    """
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    """
    Decrypts an encrypted message using the provided key
    """
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

def main():
    # Generate and save a key (only need to do this once)
    generate_and_save_key()
    
    # Load the key
    key = load_key()
    
    # Original message
    original_message = "This is a secret message!"
    print(f"Original Message: {original_message}")
    
    # Encrypt the message
    encrypted = encrypt_message(original_message, key)
    print(f"Encrypted Message: {encrypted}")
    
    # Decrypt the message
    decrypted = decrypt_message(encrypted, key)
    print(f"Decrypted Message: {decrypted}")

if __name__ == "__main__":
    main()