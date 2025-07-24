 import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# --- Configuration ---
# You can adjust these, but these are reasonable defaults.
SALT_SIZE_BYTES = 16
NONCE_SIZE_BYTES = 12  # Recommended for AES-GCM
KEY_SIZE_BYTES = 32  # AES-256
PBKDF2_ITERATIONS = 600_000 # NIST recommendation as of 2023 - adjust based on performance needs
ENCODING = 'utf-8' # For converting strings to bytes if needed

class SecureStorage:
    """
    Provides secure storage using AES-GCM authenticated encryption
    derived from a user password via PBKDF2.
    """

    def __init__(self, iterations=PBKDF2_ITERATIONS):
        """
        Initializes the SecureStorage instance.

        Args:
            iterations (int): The number of iterations for PBKDF2.
                               Higher is more secure but slower.
        """
        if iterations < 100_000:
            # Warn if iterations seem too low, though specific needs may vary.
            print(f"Warning: PBKDF2 iteration count ({iterations}) is low. "
                  f"Consider increasing it to {PBKDF2_ITERATIONS} or higher.")
        self.iterations = iterations
        self.backend = default_backend()

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Derives a cryptographic key from the password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE_BYTES,
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        return kdf.derive(password)

    def encrypt(self, plaintext_data: bytes, password: str) -> bytes:
        """
        Encrypts and authenticates data using AES-GCM.

        Args:
            plaintext_data (bytes): The data to encrypt.
            password (str): The user's password.

        Returns:
            bytes: A combined byte string containing salt, nonce, and
                   authenticated ciphertext (tag included). Format:
                   salt || nonce || ciphertext_and_tag
        """
        if not isinstance(plaintext_data, bytes):
            raise TypeError("plaintext_data must be bytes")
        if not isinstance(password, str) or not password:
             raise ValueError("password must be a non-empty string")

        password_bytes = password.encode(ENCODING)

        # 1. Generate secure random salt and nonce
        salt = os.urandom(SALT_SIZE_BYTES)
        nonce = os.urandom(NONCE_SIZE_BYTES)

        # 2. Derive the encryption key
        key = self._derive_key(password_bytes, salt)

        # 3. Encrypt using AES-GCM
        aesgcm = AESGCM(key)
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext_data, None) # No Associated Data (AAD)

        # 4. Combine parts for storage: salt + nonce + ciphertext_and_tag
        # Ensure fixed-size parts are prepended for easier parsing on decrypt
        encrypted_bundle = salt + nonce + ciphertext_and_tag
        return encrypted_bundle

    def decrypt(self, encrypted_bundle: bytes, password: str) -> bytes:
        """
        Decrypts and verifies data previously encrypted with encrypt().

        Args:
            encrypted_bundle (bytes): The combined data from encrypt().
                                     (salt || nonce || ciphertext_and_tag)
            password (str): The user's password used for encryption.

        Returns:
            bytes: The original plaintext data.

        Raises:
            ValueError: If the encrypted_bundle is too short or password invalid.
            cryptography.exceptions.InvalidTag: If authentication fails
                                                 (wrong password or data tampered).
            TypeError: If inputs are not of the expected type.
        """
        if not isinstance(encrypted_bundle, bytes):
             raise TypeError("encrypted_bundle must be bytes")
        if not isinstance(password, str) or not password:
             raise ValueError("password must be a non-empty string")

        # Expected minimum length check
        min_len = SALT_SIZE_BYTES + NONCE_SIZE_BYTES + 1 # Need at least 1 byte for ciphertext/tag
        if len(encrypted_bundle) < min_len:
            raise ValueError("Encrypted data bundle is too short to be valid.")

        password_bytes = password.encode(ENCODING)

        # 1. Extract parts
        try:
            salt = encrypted_bundle[:SALT_SIZE_BYTES]
            nonce = encrypted_bundle[SALT_SIZE_BYTES:SALT_SIZE_BYTES + NONCE_SIZE_BYTES]
            ciphertext_and_tag = encrypted_bundle[SALT_SIZE_BYTES + NONCE_SIZE_BYTES:]
        except IndexError: # Should be caught by length check, but belts and suspenders
             raise ValueError("Error parsing encrypted data bundle.")

        # 2. Derive the key (MUST use the same salt and iterations)
        key = self._derive_key(password_bytes, salt)

        # 3. Decrypt using AES-GCM
        aesgcm = AESGCM(key)
        try:
            plaintext_data = aesgcm.decrypt(nonce, ciphertext_and_tag, None) # No AAD
            return plaintext_data
        except InvalidTag:
            # This is crucial! Indicates either wrong password or tampered data.
            # Avoid giving specific error messages that leak info.
            raise InvalidTag("Decryption failed: Authentication tag mismatch.")
        except Exception as e:
            # Catch other potential crypto errors, but re-raise InvalidTag specifically
            print(f"An unexpected error occurred during decryption: {e}")
            raise # Re-raise other unexpected errors


# --- Example Usage ---

# Sensitive data (can be bytes or string)
secret_message = "This is my very secret data!"
secret_message_bytes = secret_message.encode(ENCODING)
user_password = "SuperSecretPassword123!" # Use a strong password in real life!

# File to store the encrypted data
storage_file = "secure_data.bin"

# --- Store Data ---
try:
    storage = SecureStorage() # Use default iterations
    encrypted_data = storage.encrypt(secret_message_bytes, user_password)

    # Often useful to Base64 encode for storing in text files (like JSON) or DBs
    encrypted_data_b64 = base64.b64encode(encrypted_data)
    print(f"Encrypted (Base64): {encrypted_data_b64.decode(ENCODING)}")

    # Save to file (binary mode)
    with open(storage_file, "wb") as f:
        f.write(encrypted_data)
    print(f"Encrypted data saved to {storage_file}")

except Exception as e:
    print(f"Error during encryption: {e}")


# --- Retrieve Data ---
try:
    # Load from file (binary mode)
    with open(storage_file, "rb") as f:
        encrypted_data_from_file = f.read()

    # If you used Base64, decode it first:
    # encrypted_data_from_file = base64.b64decode(encrypted_data_b64)

    storage = SecureStorage() # Use default iterations
    decrypted_data_bytes = storage.decrypt(encrypted_data_from_file, user_password)
    decrypted_message = decrypted_data_bytes.decode(ENCODING)

    print(f"\nDecryption successful!")
    print(f"Original Message: {decrypted_message}")

except FileNotFoundError:
     print(f"\nError: Storage file '{storage_file}' not found.")
except InvalidTag:
    # Handle incorrect password or tampered data gracefully
    print("\nDecryption failed: Invalid password or data has been corrupted/tampered with.")
except Exception as e:
    print(f"\nError during decryption: {e}")

# --- Test with Wrong Password ---
print("\n--- Testing with wrong password ---")
try:
     with open(storage_file, "rb") as f:
        encrypted_data_from_file = f.read()
     storage = SecureStorage()
     decrypted_data_bytes = storage.decrypt(encrypted_data_from_file, "WrongPassword!")
     print("Decryption successful? (This shouldn't happen)")
except InvalidTag:
     print("Decryption failed as expected (InvalidTag exception caught).")
except FileNotFoundError:
     print(f"Error: Storage file '{storage_file}' not found.")
except Exception as e:
     print(f"An unexpected error occurred: {e}")

# --- Clean up example file ---
# In a real application, you wouldn't necessarily delete it right away
# try:
#     os.remove(storage_file)
#     print(f"\nCleaned up {storage_file}")
# except OSError as e:
#     print(f"Error removing file {storage_file}: {e}")