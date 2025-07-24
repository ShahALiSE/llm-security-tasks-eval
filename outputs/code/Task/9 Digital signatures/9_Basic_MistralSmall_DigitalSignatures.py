 from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Generate RSA key pair
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Save the private key to a file
def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

# Load the private key from a file
def load_private_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = serialization.load_pem_private_key(pemlines, password=None,)
    return private_key

# Save the public key to a file
def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

# Load the public key from a file
def load_public_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    public_key = serialization.load_pem_public_key(pemlines)
    return public_key

# Create a digital signature
def create_signature(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify a digital signature
def verify_signature(public_key, signature, data):
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
        return True
    except InvalidSignature:
        return False

# Example usage
if __name__ == "__main__":
    # Generate keys
    private_key, public_key = generate_keys()

    # Save keys to files
    save_private_key(private_key, 'private_key.pem')
    save_public_key(public_key, 'public_key.pem')

    # Load keys from files
    private_key = load_private_key('private_key.pem')
    public_key = load_public_key('public_key.pem')

    # Data to sign
    data = b"Message to be signed"

    # Create a signature
    signature = create_signature(private_key, data)
    print("Signature created.")

    # Verify the signature
    is_valid = verify_signature(public_key, signature, data)
    print("Signature valid:", is_valid)
