 from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils

# Generate a private key for signing
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Derive the public key for verification
public_key = private_key.public_key()

# Data to be signed
data = b"Message to be signed"

# Sign the data
signature = private_key.sign(
    data,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("Signature:", signature)

# Verify the signature
try:
    public_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature is valid.")
except Exception as e:
    print("Signature is invalid:", e)
