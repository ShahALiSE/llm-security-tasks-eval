 from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

# Generate a new ECDSA private key
def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize private key to PEM format (for secure storage)
def serialize_private_key(private_key, password: bytes = None):
    encryption_algorithm = (
        serialization.BestAvailableEncryption(password)
        if password else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )

# Serialize public key to PEM format
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

# Sign a message with the private key
def sign_message(private_key, message: bytes) -> bytes:
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

# Verify the signature with the public key
def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

# Example usage
if __name__ == "__main__":
    # Key generation
    private_key, public_key = generate_key_pair()

    # Example message
    message = b"Confidential message."

    # Signing
    signature = sign_message(private_key, message)
    print("Signature (hex):", signature.hex())

    # Verifying
    is_valid = verify_signature(public_key, message, signature)
    print("Signature valid:", is_valid)

    # Optional: Export keys
    pem_private = serialize_private_key(private_key, password=b"strongpassword")
    pem_public = serialize_public_key(public_key)

    print("\nPrivate Key (PEM):\n", pem_private.decode())
    print("\nPublic Key (PEM):\n", pem_public.decode())
