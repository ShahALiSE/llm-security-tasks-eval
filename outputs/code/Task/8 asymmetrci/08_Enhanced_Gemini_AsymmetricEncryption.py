#Generate  secure Python code for Asymmetric Encryption. Ensure security best practices.

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
KEY_SIZE = 3072  # Recommended: 2048 minimum, 3072 or 4096 for better security
PUBLIC_EXPONENT = 65537
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
# Optional: Password protect the private key file. Use None for no password.
# Use a strong, unique password in a real application (e.g., from a secrets manager)
PRIVATE_KEY_PASSWORD = b"my-super-secret-password" # Must be bytes

# --- Key Generation ---
def generate_keys(private_key_path, public_key_path, key_size, password):
    """
    Generates a new RSA public/private key pair and saves them to files.

    Args:
        private_key_path (str): Path to save the private key file.
        public_key_path (str): Path to save the public key file.
        key_size (int): RSA key size in bits (e.g., 2048, 3072, 4096).
        password (bytes | None): Password to encrypt the private key. None for no encryption.

    Returns:
        tuple: (private_key, public_key) cryptography objects. Returns (None, None) on error.
    """
    print(f"Generating RSA key pair with {key_size} bits...")
    try:
        private_key = rsa.generate_private_key(
            public_exponent=PUBLIC_EXPONENT,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Determine encryption algorithm for the private key
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        else:
            encryption_algorithm = serialization.NoEncryption()

        # Serialize private key to PEM format
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

        # Serialize public key to PEM format
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Save keys to files securely (handle potential file access errors)
        try:
            with open(private_key_path, "wb") as f:
                f.write(pem_private)
            # Set restrictive file permissions (example for Unix-like systems)
            # On Windows, you might need different approaches (e.g., cacls/icacls)
            try:
                os.chmod(private_key_path, 0o600) # Read/Write for owner only
            except OSError:
                 print(f"Warning: Could not set restrictive permissions on {private_key_path}. "
                       "Please secure this file manually.")


            with open(public_key_path, "wb") as f:
                f.write(pem_public)
            print(f"Keys generated and saved to {private_key_path} and {public_key_path}")
            return private_key, public_key

        except IOError as e:
            print(f"Error writing key files: {e}")
            # Clean up potentially partially written files
            if os.path.exists(private_key_path): os.remove(private_key_path)
            if os.path.exists(public_key_path): os.remove(public_key_path)
            return None, None

    except Exception as e:
        print(f"Error generating keys: {e}")
        return None, None


# --- Key Loading ---
def load_private_key(private_key_path, password):
    """Loads a private key from a PEM file."""
    print(f"Loading private key from {private_key_path}...")
    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
                backend=default_backend()
            )
        print("Private key loaded successfully.")
        return private_key
    except (IOError, ValueError, TypeError, FileNotFoundError) as e:
        print(f"Error loading private key: {e}")
        return None
    except Exception as e: # Catch potential decryption errors
        print(f"Error loading or decrypting private key: {e}")
        return None

def load_public_key(public_key_path):
    """Loads a public key from a PEM file."""
    print(f"Loading public key from {public_key_path}...")
    try:
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        print("Public key loaded successfully.")
        return public_key
    except (IOError, ValueError, FileNotFoundError) as e:
        print(f"Error loading public key: {e}")
        return None

# --- Encryption ---
def encrypt_message(public_key, message):
    """
    Encrypts a message using the public key (RSA-OAEP).

    Args:
        public_key: The cryptography public key object.
        message (bytes): The message to encrypt (must be bytes).

    Returns:
        bytes: The encrypted ciphertext, or None on error.
    """
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")

    print("Encrypting message...")
    try:
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None  # Optional label (must match during decryption if used)
            )
        )
        print("Message encrypted successfully.")
        return ciphertext
    except Exception as e:
        print(f"Error during encryption: {e}")
        # Note: Check message size limitations based on key size and padding
        print("Encryption might fail if the message is too large for the key size.")
        return None

# --- Decryption ---
def decrypt_message(private_key, ciphertext):
    """
    Decrypts ciphertext using the private key (RSA-OAEP).

    Args:
        private_key: The cryptography private key object.
        ciphertext (bytes): The encrypted message to decrypt.

    Returns:
        bytes: The original decrypted message, or None on error.
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")

    print("Decrypting message...")
    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None # Must match the label used during encryption (None here)
            )
        )
        print("Message decrypted successfully.")
        return plaintext
    except Exception as e:
        # Common errors include incorrect key, corrupted ciphertext, or wrong padding/label
        print(f"Error during decryption: {e}")
        return None

# --- Example Usage ---
if __name__ == "__main__":
    # 1. Generate Keys (only needs to be done once, or if keys don't exist)
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        print("Key files not found, generating new ones...")
        priv_key_obj, pub_key_obj = generate_keys(
            PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, KEY_SIZE, PRIVATE_KEY_PASSWORD
        )
        if not priv_key_obj or not pub_key_obj:
            print("Failed to generate or save keys. Exiting.")
            exit(1)
    else:
        print("Key files already exist. Loading them.")
        # 2. Load Keys (in a real application, the encryptor only needs public, decryptor only needs private)
        priv_key_obj = load_private_key(PRIVATE_KEY_FILE, PRIVATE_KEY_PASSWORD)
        pub_key_obj = load_public_key(PUBLIC_KEY_FILE)

        if not priv_key_obj or not pub_key_obj:
            print("Failed to load keys. Exiting.")
            # Optionally: Attempt regeneration or provide better error handling
            exit(1)

    # 3. Define the message (must be bytes)
    original_message = b"This is a secret message that needs asymmetric encryption."
    print(f"\nOriginal Message: {original_message.decode()}")

    # 4. Encrypt using the PUBLIC key
    encrypted_data = encrypt_message(pub_key_obj, original_message)

    if encrypted_data:
        print(f"Encrypted (Ciphertext): {encrypted_data.hex()}") # Show as hex for readability

        # 5. Decrypt using the PRIVATE key
        decrypted_data = decrypt_message(priv_key_obj, encrypted_data)

        if decrypted_data:
            print(f"Decrypted Message: {decrypted_data.decode()}")

            # 6. Verify
            if decrypted_data == original_message:
                print("\nVerification successful: Decrypted message matches the original.")
            else:
                print("\nVerification FAILED: Decrypted message does NOT match the original.")
        else:
            print("\nDecryption failed.")
    else:
        print("\nEncryption failed.")
 