 import os
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding as sym_padding # Although not directly used for signing, good to be aware of for related crypto
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# --- Configuration ---
CURVE = ec.SECP384r1()
HASH_ALGORITHM = hashes.SHA384()
PRIVATE_KEY_FILENAME = "ecdsa_private_key.pem"
PUBLIC_KEY_FILENAME = "ecdsa_public_key.pem"
SALT_SIZE = 16 # Recommended salt size for PBKDF2

# --- Key Management Functions ---

def generate_keys(private_key_path=PRIVATE_KEY_FILENAME, public_key_path=PUBLIC_KEY_FILENAME, password=None):
    """
    Generates a new ECDSA private/public key pair and saves them to files.

    Args:
        private_key_path (str): Path to save the private key.
        public_key_path (str): Path to save the public key.
        password (bytes): Optional password to encrypt the private key. If None,
                          the key is saved unencrypted (NOT RECOMMENDED for production).

    Returns:
        tuple: (private_key, public_key) objects.
               Returns (None, None) if password is required but not provided correctly.
    """
    private_key = ec.generate_private_key(CURVE, default_backend())
    public_key = private_key.public_key()

    # Determine encryption algorithm
    if password:
        print("Encrypting private key...")
        encryption_algorithm = serialization.BestAvailableEncryption(password)
    else:
        print("WARNING: Saving private key without password protection.")
        encryption_algorithm = serialization.NoEncryption()

    # Serialize and save private key
    try:
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        with open(private_key_path, "wb") as pem_out:
            pem_out.write(pem_private)
        # Set file permissions (Unix-like systems) for security
        try:
            os.chmod(private_key_path, 0o600) # Read/write only for owner
        except OSError as e:
            print(f"Warning: Could not set file permissions for {private_key_path}: {e}")
        print(f"Private key saved to {private_key_path}")

    except Exception as e:
        print(f"Error saving private key: {e}")
        return None, None # Indicate failure

    # Serialize and save public key
    try:
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, "wb") as pem_out:
            pem_out.write(pem_public)
        print(f"Public key saved to {public_key_path}")
    except Exception as e:
        print(f"Error saving public key: {e}")
        # Optionally clean up private key file if public key fails
        # os.remove(private_key_path)
        return None, None # Indicate failure


    return private_key, public_key

def load_private_key(filepath=PRIVATE_KEY_FILENAME, password=None):
    """Loads a private key from a PEM file."""
    try:
        with open(filepath, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
                backend=default_backend()
            )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
             raise TypeError("Key is not an Elliptic Curve private key.")
        return private_key
    except (FileNotFoundError, TypeError, ValueError) as e:
        print(f"Error loading private key from {filepath}: {e}")
        return None
    except Exception as e: # Catch other potential crypto errors
        print(f"An unexpected error occurred loading the private key: {e}")
        return None


def load_public_key(filepath=PUBLIC_KEY_FILENAME):
    """Loads a public key from a PEM file."""
    try:
        with open(filepath, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
             raise TypeError("Key is not an Elliptic Curve public key.")
        return public_key
    except (FileNotFoundError, TypeError, ValueError) as e:
        print(f"Error loading public key from {filepath}: {e}")
        return None
    except Exception as e: # Catch other potential crypto errors
        print(f"An unexpected error occurred loading the public key: {e}")
        return None

# --- Signing and Verification Functions ---

def sign_data(private_key, data):
    """
    Signs data using the provided private key.

    Args:
        private_key (ec.EllipticCurvePrivateKey): The private key object.
        data (bytes): The data to sign (must be bytes).

    Returns:
        bytes: The signature, or None if signing fails.
    """
    if not isinstance(data, bytes):
        raise TypeError("Data to sign must be bytes.")
    if not private_key:
        print("Error: Private key not provided or invalid.")
        return None

    try:
        signature = private_key.sign(
            data,
            ec.ECDSA(HASH_ALGORITHM) # The library handles hashing internally
        )
        return signature
    except Exception as e:
        print(f"Error during signing: {e}")
        return None

def verify_signature(public_key, signature, data):
    """
    Verifies a signature using the public key and original data.

    Args:
        public_key (ec.EllipticCurvePublicKey): The public key object.
        signature (bytes): The signature to verify.
        data (bytes): The original data that was signed (must be bytes).

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    if not isinstance(data, bytes):
        raise TypeError("Data for verification must be bytes.")
    if not isinstance(signature, bytes):
        raise TypeError("Signature must be bytes.")
    if not public_key:
        print("Error: Public key not provided or invalid.")
        return False

    try:
        # The verify method raises an InvalidSignature exception if verification fails
        public_key.verify(
            signature,
            data,
            ec.ECDSA(HASH_ALGORITHM) # Must match the signing algorithm/hash
        )
        return True
    except InvalidSignature:
        return False # Signature is invalid
    except Exception as e:
        print(f"Error during verification: {e}")
        return False # Other errors occurred

# --- Example Usage ---

if __name__ == "__main__":
    # --- Configuration ---
    GENERATE_NEW_KEYS = False # Set to True only if you need new keys
    PRIVATE_KEY_PASSWORD_NEEDED = True # Recommended for security

    # --- Key Handling ---
    private_key = None
    public_key = None
    key_password = None

    if PRIVATE_KEY_PASSWORD_NEEDED:
        # Securely get password (avoids echoing to screen)
        try:
            key_password_str = getpass.getpass("Enter password for private key (leave blank for no password): ")
            if key_password_str:
                 key_password = key_password_str.encode('utf-8') # Passwords must be bytes
            else:
                 print("Proceeding without password protection (less secure).")
                 key_password = None
        except Exception as e:
            print(f"Error getting password: {e}")
            exit(1) # Exit if password handling fails critically


    if GENERATE_NEW_KEYS or not os.path.exists(PRIVATE_KEY_FILENAME) or not os.path.exists(PUBLIC_KEY_FILENAME):
        print("Generating new keys...")
        private_key, public_key = generate_keys(password=key_password)
        if not private_key:
             print("Key generation failed. Exiting.")
             exit(1)
    else:
        print("Loading existing keys...")
        private_key = load_private_key(password=key_password)
        if not private_key:
             print(f"Failed to load private key. Check password or file '{PRIVATE_KEY_FILENAME}'. Exiting.")
             exit(1)

        public_key = load_public_key()
        if not public_key:
            print(f"Failed to load public key from '{PUBLIC_KEY_FILENAME}'. Exiting.")
            exit(1)

    # --- Signing ---
    message = b"This is the data to be signed. Integrity and authenticity matter!"
    print(f"\nOriginal message: {message.decode()}")

    signature = sign_data(private_key, message)

    if signature:
        print(f"Generated Signature (hex): {signature.hex()}")

        # --- Verification ---
        is_valid = verify_signature(public_key, signature, message)
        print(f"\nVerifying signature with original data...")
        if is_valid:
            print("Result: Signature is VALID.")
        else:
            print("Result: Signature is INVALID.")

        # --- Tamper Test ---
        tampered_message = b"This is DIFFERENT data."
        print(f"\nVerifying signature with tampered data ({tampered_message.decode()})...")
        is_valid_tampered = verify_signature(public_key, signature, tampered_message)
        if is_valid_tampered:
            print("Result: Signature is VALID (This should NOT happen!).")
        else:
            print("Result: Signature is INVALID (Correctly detected tampering).")

        # --- Wrong Key Test ---
        print("\nGenerating temporary wrong key for verification test...")
        wrong_private_key = ec.generate_private_key(CURVE, default_backend())
        wrong_public_key = wrong_private_key.public_key()
        print("Verifying signature with wrong public key...")
        is_valid_wrong_key = verify_signature(wrong_public_key, signature, message)
        if is_valid_wrong_key:
            print("Result: Signature is VALID (This should NOT happen!).")
        else:
            print("Result: Signature is INVALID (Correctly detected wrong key).")

    else:
        print("Signing failed. Cannot proceed with verification.")