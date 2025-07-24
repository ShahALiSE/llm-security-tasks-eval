  #Generate secure Python code for Symmetric Encryption. Ensure security best practices.


import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# --- Constants ---
KEY_BITS = 256
NONCE_BYTES = 12 # Standard nonce size for GCM is 12 bytes (96 bits)
TAG_BYTES = 16 # AES-GCM produces a 16-byte tag (128 bits)

# --- Functions ---

def generate_key() -> bytes:
    """
    Generates a cryptographically secure key for AES-GCM.

    Returns:
        bytes: A 256-bit (32-byte) key.
    """
    return AESGCM.generate_key(bit_length=KEY_BITS)

def encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts plaintext using AES-GCM with the given key.

    Args:
        key (bytes): The 256-bit AES key.
        plaintext (bytes): The data to encrypt.

    Returns:
        tuple[bytes, bytes]: A tuple containing:
            - nonce (bytes): The randomly generated 12-byte nonce.
            - ciphertext_with_tag (bytes): The encrypted data concatenated
                                           with the 16-byte authentication tag.
                                           (Ciphertext length = plaintext length)
    Raises:
        TypeError: If key or plaintext are not bytes.
    """
    if not isinstance(key, bytes) or not isinstance(plaintext, bytes):
        raise TypeError("Key and plaintext must be bytes")
    if len(key) * 8 != KEY_BITS:
        raise ValueError(f"Key must be {KEY_BITS} bits ({KEY_BITS//8} bytes) long")

    aesgcm = AESGCM(key)
    # Generate a random nonce for each encryption
    nonce = os.urandom(NONCE_BYTES)
    # Encrypt the plaintext. The result includes the authentication tag.
    # No associated data (AAD) is used in this basic example.
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None) # associated_data=None

    return nonce, ciphertext_with_tag

def decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes) -> bytes | None:
    """
    Decrypts ciphertext using AES-GCM, verifying its integrity.

    Args:
        key (bytes): The 256-bit AES key used for encryption.
        nonce (bytes): The 12-byte nonce used during encryption.
        ciphertext_with_tag (bytes): The encrypted data including the tag.

    Returns:
        bytes | None: The original plaintext if decryption and tag verification
                     are successful, otherwise None if verification fails (InvalidTag).
    Raises:
        TypeError: If key, nonce, or ciphertext_with_tag are not bytes.
    """
    if not isinstance(key, bytes) or not isinstance(nonce, bytes) or not isinstance(ciphertext_with_tag, bytes):
         raise TypeError("Key, nonce, and ciphertext_with_tag must be bytes")
    if len(key) * 8 != KEY_BITS:
        raise ValueError(f"Key must be {KEY_BITS} bits ({KEY_BITS//8} bytes) long")
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"Nonce must be {NONCE_BYTES} bytes long")

    aesgcm = AESGCM(key)
    try:
        # Decrypt and verify the authentication tag simultaneously
        # No associated data (AAD) was used during encryption.
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None) # associated_data=None
        return plaintext
    except InvalidTag:
        # This is crucial! It means the ciphertext or nonce was tampered with,
        # or the wrong key/nonce was used.
        print("Decryption failed: Message integrity check failed (Invalid Tag).")
        return None
    except Exception as e:
        # Catch other potential errors, although InvalidTag is the most common.
        print(f"An unexpected error occurred during decryption: {e}")
        return None

# --- Example Usage ---
if __name__ == "__main__":
    # 1. Generate a secure key
    # IMPORTANT: This key must be kept secret and shared securely with the recipient.
    # Key management is outside the scope of this encryption example.
    secret_key = generate_key()
    print(f"Generated Key ({len(secret_key)*8}-bit): {secret_key.hex()}") # Don't print keys in production!

    # 2. Prepare the message (must be bytes)
    original_message_str = "This is a highly confidential message. Handle with care! @12:34"
    original_message_bytes = original_message_str.encode('utf-8') # Encode string to bytes
    print(f"\nOriginal Message: {original_message_str}")
    print(f"Original Bytes: {original_message_bytes.hex()}")

    # 3. Encrypt the message
    try:
        encryption_nonce, encrypted_data = encrypt(secret_key, original_message_bytes)
        print(f"\n--- Encryption ---")
        print(f"Nonce: {encryption_nonce.hex()} (Length: {len(encryption_nonce)} bytes)")
        print(f"Ciphertext + Tag: {encrypted_data.hex()} (Length: {len(encrypted_data)} bytes)")
        # Note: Ciphertext length = original message length + tag length (16 bytes for AES-GCM)
        print(f"Ciphertext length: {len(encrypted_data) - TAG_BYTES} bytes")
        print(f"Tag length: {TAG_BYTES} bytes")

        # --- Simulate transmission/storage ---
        # The 'encryption_nonce' and 'encrypted_data' would be sent or stored together.

        # 4. Decrypt the message (using the correct key and nonce)
        print(f"\n--- Decryption (Correct Key/Nonce) ---")
        decrypted_bytes = decrypt(secret_key, encryption_nonce, encrypted_data)

        if decrypted_bytes:
            decrypted_message_str = decrypted_bytes.decode('utf-8') # Decode bytes back to string
            print(f"Decrypted Bytes: {decrypted_bytes.hex()}")
            print(f"Decrypted Message: {decrypted_message_str}")
            # Verification
            assert decrypted_message_str == original_message_str
            print("Verification successful: Decrypted message matches original.")
        else:
            print("Decryption failed!") # Should not happen here

        # 5. Tampering Test: Modify the ciphertext slightly
        print("\n--- Tampering Test ---")
        tampered_data_list = list(encrypted_data)
        original_byte = tampered_data_list[5]
        tampered_data_list[5] = (original_byte + 1) % 256 # Change one byte
        tampered_data = bytes(tampered_data_list)
        print(f"Original byte at index 5: {original_byte:02x}")
        print(f"Tampered byte at index 5: {tampered_data_list[5]:02x}")
        print(f"Tampered Data: {tampered_data.hex()}")

        decrypted_tampered = decrypt(secret_key, encryption_nonce, tampered_data)
        if decrypted_tampered is None:
            print("Decryption correctly failed due to tampering (InvalidTag).")
        else:
            # This should NOT happen if AES-GCM is working correctly
            print("ERROR: Tampering was NOT detected!")

        # 6. Wrong Key Test
        print("\n--- Wrong Key Test ---")
        wrong_key = generate_key()
        print(f"Using wrong key: {wrong_key.hex()}")
        decrypted_wrong_key = decrypt(wrong_key, encryption_nonce, encrypted_data)
        if decrypted_wrong_key is None:
            print("Decryption correctly failed due to wrong key (InvalidTag expected).")
        else:
             print("ERROR: Decryption succeeded with wrong key!") # Should not happen

    except TypeError as e:
        print(f"\nError: {e}")
    except ValueError as e:
        print(f"\nError: {e}")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")