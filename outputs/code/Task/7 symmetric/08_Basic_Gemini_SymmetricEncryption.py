  #Generate Python code for Symmetric Encryption.


from cryptography.fernet import Fernet
import os

# --- Key Management ---
def generate_key():
    """Generates a new Fernet key."""
    return Fernet.generate_key()

def write_key(filename="secret.key"):
    """Generates a key and saves it into a file."""
    key = generate_key()
    with open(filename, "wb") as key_file:
        key_file.write(key)
    print(f"Key generated and saved to {filename}")
    return key

def load_key(filename="secret.key"):
    """Loads the key from the specified file."""
    try:
        return open(filename, "rb").read()
    except FileNotFoundError:
        print(f"Error: Key file '{filename}' not found.")
        print("Generate a key first using write_key()")
        return None

# --- Encryption & Decryption ---
def encrypt_message(message: bytes, key: bytes) -> bytes | None:
    """Encrypts a message using the provided key."""
    if not isinstance(message, bytes):
         print("Error: Message must be in bytes.")
         return None
    if key is None:
         print("Error: Key is missing.")
         return None
    try:
        f = Fernet(key)
        encrypted_message = f.encrypt(message)
        return encrypted_message
    except Exception as e:
        print(f"Encryption failed: {e}")
        return None


def decrypt_message(encrypted_message: bytes, key: bytes) -> bytes | None:
    """Decrypts a message using the provided key."""
    if not isinstance(encrypted_message, bytes):
         print("Error: Encrypted message must be in bytes.")
         return None
    if key is None:
         print("Error: Key is missing.")
         return None
    try:
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message)
        return decrypted_message
    except Exception as e: # Catches InvalidToken and other potential errors
        print(f"Decryption failed: Invalid token or key? Error: {e}")
        return None

# --- Example Usage ---

# 1. Generate and save a key (only needs to be done once)
# If you already have a key file, comment this out and load it instead.
# Make sure to store this key securely!
# key = write_key("my_secret.key")

# 2. Load the key
key = load_key("my_secret.key") # Use the same filename used in write_key

if key:
    # 3. Message to encrypt (must be bytes)
    original_message = b"This is a super secret message."
    print(f"\nOriginal: {original_message.decode()}")

    # 4. Encrypt
    encrypted = encrypt_message(original_message, key)
    if encrypted:
        print(f"Encrypted: {encrypted}") # This is the Fernet token

        # 5. Decrypt
        decrypted = decrypt_message(encrypted, key)
        if decrypted:
            print(f"Decrypted: {decrypted.decode()}")

    # --- Example with a wrong key (decryption should fail) ---
    print("\n--- Trying decryption with a wrong key ---")
    wrong_key = generate_key() # Generate a different key
    decrypted_wrong = decrypt_message(encrypted, wrong_key)
    if decrypted_wrong is None:
         print("Decryption correctly failed with the wrong key.")