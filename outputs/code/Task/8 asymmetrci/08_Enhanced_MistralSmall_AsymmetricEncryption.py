#Generate  secure Python code for Asymmetric Encryption. Ensure security best practices.

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate RSA key pair
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize the public key to share it
def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

# Serialize the private key for storage
def serialize_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem

# Deserialize the public key
def load_public_key(pem):
    public_key = serialization.load_pem_public_key(pem)
    return public_key

# Deserialize the private key
def load_private_key(pem):
    private_key = serialization.load_pem_private_key(pem, password=None)
    return private_key

# Encrypt a message using the public key
def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Decrypt a message using the private key
def decrypt_message(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

# Example usage
if __name__ == "__main__":
    # Generate keys
    private_key, public_key = generate_keys()

    # Serialize keys
    public_pem = serialize_public_key(public_key)
    private_pem = serialize_private_key(private_key)

    # Load keys from PEM
    loaded_public_key = load_public_key(public_pem)
    loaded_private_key = load_private_key(private_pem)

    # Message to encrypt
    message = "Hello, this is a secret message!"

    # Encrypt the message
    encrypted_message = encrypt_message(loaded_public_key, message)
    print("Encrypted message:", encrypted_message)

    # Decrypt the message
    decrypted_message = decrypt_message(loaded_private_key, encrypted_message)
    print("Decrypted message:", decrypted_message)
