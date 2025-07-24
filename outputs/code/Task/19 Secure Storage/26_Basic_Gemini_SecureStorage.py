 # Import necessary modules from the cryptography library
from cryptography.fernet import Fernet
import os
import json
import traceback

# --- Key Management ---
# WARNING: Secure key storage is crucial! Avoid storing keys directly in code or simple files for production.
# Consider environment variables, OS keychains (e.g., using the 'keyring' library),
# or dedicated secret management services (AWS Secrets Manager, Google Secret Manager, HashiCorp Vault).

KEY_FILE = 'secret.key'

def generate_key():
    """Generates a new Fernet key and saves it to a file (for example purposes only)."""
    key = Fernet.generate_key()
    try:
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        print(f"Key generated and saved to {KEY_FILE}. PROTECT THIS FILE!")
        return key
    except IOError as e:
        print(f"Error saving key file: {e}")
        return None

def load_key():
    """Loads the Fernet key from a file (for example purposes only)."""
    try:
        with open(KEY_FILE, 'rb') as key_file:
            key = key_file.read()
        return key
    except FileNotFoundError:
        return None
    except IOError as e:
        print(f"Error reading key file: {e}")
        return None

# --- Encryption/Decryption Functions ---

def encrypt_data(data_to_encrypt, key):
    """Encrypts data (string, bytes, dict, list) using the provided key."""
    if not key:
        print("Encryption failed: No key provided.")
        return None
    try:
        f = Fernet(key)
    except Exception as e:
        print(f"Error initializing Fernet with key: {e}")
        # traceback.print_exc() # Uncomment for detailed debug info
        return None

    data_bytes = None
    if isinstance(data_to_encrypt, (dict, list)):
        try:
            data_bytes = json.dumps(data_to_encrypt).encode('utf-8')
        except Exception as e:
            print(f"Error JSON encoding data: {e}")
            return None
    elif isinstance(data_to_encrypt, str):
        try:
            data_bytes = data_to_encrypt.encode('utf-8')
        except Exception as e:
            print(f"Error UTF-8 encoding string: {e}")
            return None
    elif isinstance(data_to_encrypt, bytes):
        data_bytes = data_to_encrypt
    else:
        print(f"Encryption failed: Data type {type(data_to_encrypt)} not supported.")
        return None

    if data_bytes is None:
        print("Encryption failed: Could not convert data to bytes.")
        return None

    try:
        return f.encrypt(data_bytes)
    except Exception as e:
        print(f"Encryption error during f.encrypt: {e}")
        # traceback.print_exc() # Uncomment for detailed debug info
        return None

def decrypt_data(encrypted_data, key):
    """Decrypts data using the provided key, attempting to restore original type."""
    if not key:
        print("Decryption failed: No key provided.")
        return None
    if not encrypted_data:
        print("Decryption failed: No encrypted data provided.")
        return None

    try:
        f = Fernet(key)
    except Exception as e:
        print(f"Error initializing Fernet with key for decryption: {e}")
        # traceback.print_exc() # Uncomment for detailed debug info
        return None

    try:
        decrypted_bytes = f.decrypt(encrypted_data)

        # Try parsing as JSON first
        try:
            return json.loads(decrypted_bytes.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
             # If not JSON, try decoding as plain string
             try:
                 return decrypted_bytes.decode('utf-8')
             except UnicodeDecodeError:
                 # Otherwise, return raw bytes
                 return decrypted_bytes

    except Exception as e: # Catches InvalidToken, etc.
        print(f"Decryption error: {e}. (Wrong key or corrupted data?)")
        # traceback.print_exc() # Uncomment for detailed debug info
        return None

# --- Example Usage ---

# 1. Load or generate key
key = load_key()
if not key:
    print(f"Key file '{KEY_FILE}' not found, generating a new one.")
    key = generate_key()

if key:
    # 2. Define data and output files
    sensitive_data_string = "This is my super secret message!"
    sensitive_data_dict = {"api_key": "123-abc-789-xyz", "user": "admin"}
    output_file_string = "encrypted_string.bin"
    output_file_dict = "encrypted_dict.bin"

    # --- String Example ---
    print("\n--- String Encryption/Decryption ---")
    encrypted_string = encrypt_data(sensitive_data_string, key)
    if encrypted_string:
        try:
            # Store encrypted data
            with open(output_file_string, 'wb') as f: f.write(encrypted_string)
            print(f"Encrypted string saved to {output_file_string}")
            # Load encrypted data
            with open(output_file_string, 'rb') as f: loaded_encrypted_string = f.read()
            # Decrypt
            decrypted_string = decrypt_data(loaded_encrypted_string, key)
            print(f"Decrypted String: '{decrypted_string}'")
            assert sensitive_data_string == decrypted_string
            print("String Assertion Passed.")
        except Exception as e: print(f"An error occurred: {e}")
    else: print("Encryption failed for string.")

    # --- Dictionary Example ---
    print("\n--- Dictionary Encryption/Decryption ---")
    encrypted_dict_data = encrypt_data(sensitive_data_dict, key)
    if encrypted_dict_data:
        try:
            # Store encrypted data
            with open(output_file_dict, 'wb') as f: f.write(encrypted_dict_data)
            print(f"Encrypted dictionary saved to {output_file_dict}")
            # Load encrypted data
            with open(output_file_dict, 'rb') as f: loaded_encrypted_dict_data = f.read()
            # Decrypt
            decrypted_dict = decrypt_data(loaded_encrypted_dict_data, key)
            print(f"Decrypted Dictionary: {decrypted_dict}")
            assert sensitive_data_dict == decrypted_dict
            print("Dictionary Assertion Passed.")
        except Exception as e: print(f"An error occurred: {e}")
    else: print("Encryption failed for dictionary.")
else:
    print("\nCould not load or generate a key. Aborting example.")