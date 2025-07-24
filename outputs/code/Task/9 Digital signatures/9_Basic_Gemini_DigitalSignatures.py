 # Import necessary modules from the cryptography library
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# --- 1. Key Generation ---
# Generate a new RSA private key.
# public_exponent is usually 65537.
# key_size determines the strength (e.g., 2048 or 4096 bits).
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Get the corresponding public key from the private key.
public_key = private_key.public_key()

# (Optional) Serialize keys for storage or transmission
# Serialize private key to PEM format (you could protect it with a password)
pem_private_key = private_key.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.PKCS8,
   encryption_algorithm=serialization.NoEncryption() # Or use BestAvailableEncryption(b'your-password')
)

# Serialize public key to PEM format
pem_public_key = public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# You can save these PEM strings to files or transmit them.
# For example:
# with open("private_key.pem", "wb") as f:
#     f.write(pem_private_key)
# with open("public_key.pem", "wb") as f:
#     f.write(pem_public_key)

# If loading keys from PEM files:
# with open("private_key.pem", "rb") as key_file:
#     private_key_loaded = serialization.load_pem_private_key(
#         key_file.read(),
#         password=None # Or b'your-password' if encrypted
#     )
# with open("public_key.pem", "rb") as key_file:
#     public_key_loaded = serialization.load_pem_public_key(
#         key_file.read()
#     )


# --- 2. Signing a Message ---
# The message to be signed (must be bytes).
message = b"This is the secret message to sign."

# Sign the message using the private key.
# PSS (Probabilistic Signature Scheme) padding is recommended for RSA.
# MGF1 (Mask Generation Function 1) is often used with PSS.
# SHA256 is a common and secure hash algorithm.
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print(f"Original Message: {message.decode()}")
print(f"Signature (hex): {signature.hex()}") # Display signature in hex format

# --- 3. Verifying the Signature ---
# The verifier needs the public key, the original message, and the signature.
try:
    # Attempt to verify the signature using the public key.
    # The padding and hash algorithm MUST match those used during signing.
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("\nSignature Verification Successful: The signature is valid.")

except InvalidSignature:
    print("\nSignature Verification Failed: The signature is invalid.")
except Exception as e:
    print(f"\nAn error occurred during verification: {e}")

# --- Example: Verification Failure (tampered message) ---
tampered_message = b"This is NOT the secret message to sign."

print(f"\nAttempting verification with tampered message: {tampered_message.decode()}")
try:
    public_key.verify(
        signature, # Using the original signature
        tampered_message, # But with the tampered message
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature Verification Successful (This should not happen!)")
except InvalidSignature:
    print("Signature Verification Failed: The signature is invalid (as expected for tampered message).")
except Exception as e:
    print(f"An error occurred during verification: {e}")