from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Key Generation
def generate_keys():
    """
    Generate RSA private and public keys
    Returns: (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Signature Creation
def sign_message(private_key, message):
    """
    Sign a message using private key
    Returns: signature (bytes)
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Signature Verification
def verify_signature(public_key, message, signature):
    """
    Verify a message signature using public key
    Returns: Boolean indicating verification success
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# Example usage
if __name__ == "__main__":
    # Generate keys
    private_key, public_key = generate_keys()

    # Original message
    message = b"Hello, world!"

    # Create signature
    signature = sign_message(private_key, message)
    print(f"Signature: {signature.hex()}")

    # Verify valid signature
    is_valid = verify_signature(public_key, message, signature)
    print(f"Signature valid: {is_valid}")  # Should print True

    # Verify with tampered message
    tampered_message = b"Hello, world! "
    is_valid_tampered = verify_signature(public_key, tampered_message, signature)
    print(f"Tampered signature valid: {is_valid_tampered}")  # Should print False