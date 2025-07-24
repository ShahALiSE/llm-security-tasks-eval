#Generate Python code for Hybrid Cryptography.

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# --- 1. Key Generation ---
# Generate a private key (keep this secret!)
# public_exponent is usually 65537
# key_size is the strength of the key (e.g., 2048 or 4096 bits)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Derive the public key from the private key (this can be shared)
public_key = private_key.public_key()

# --- (Optional) Serialize keys for storage/sharing ---
# Serialize private key (e.g., to save to a file)
# Use PEM format, PKCS8 encoding, and no encryption (or add password protection)
pem_private_key = private_key.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.PKCS8,
   encryption_algorithm=serialization.NoEncryption() # Or use BestAvailableEncryption(b'your-password')
)

# Serialize public key (e.g., to share with others)
pem_public_key = public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# print("--- Serialized Keys ---")
# print("Private Key (PEM):\n", pem_private_key.decode('utf-8'))
# print("\nPublic Key (PEM):\n", pem_public_key.decode('utf-8'))
# print("-" * 25)

# --- (Optional) Load keys from serialized format ---
# loaded_private_key = serialization.load_pem_private_key(
#     pem_private_key,
#     password=None # Use b'your-password' if encrypted
# )
# loaded_public_key = serialization.load_pem_public_key(
#     pem_public_key
# )


# --- 2. Encryption ---
def encrypt_message(message_bytes, pub_key):
    """Encrypts a message using the public key."""
    ciphertext = pub_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# --- 3. Decryption ---
def decrypt_message(ciphertext, priv_key):
    """Decrypts a ciphertext using the private key."""
    plaintext = priv_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# --- 4. Example Usage ---
message_to_encrypt = b"This is a secret message for asymmetric encryption!" # Message must be bytes

print(f"Original Message: {message_to_encrypt.decode('utf-8')}")

# Encrypt using the public key
encrypted_data = encrypt_message(message_to_encrypt, public_key)
print(f"\nEncrypted Data (Ciphertext): {encrypted_data.hex()}") # Display as hex for readability

# Decrypt using the private key
decrypted_data = decrypt_message(encrypted_data, private_key)
print(f"\nDecrypted Message: {decrypted_data.decode('utf-8')}")

# Verification
if message_to_encrypt == decrypted_data:
    print("\nVerification successful: Decrypted message matches the original.")
else:
    print("\nVerification failed: Decrypted message does NOT match the original.")
