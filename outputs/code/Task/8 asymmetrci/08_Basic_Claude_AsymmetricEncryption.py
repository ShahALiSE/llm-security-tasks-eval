from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64


def generate_key_pair():
    """Generate a pair of RSA private and public keys"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Extract public key from private key
    public_key = private_key.public_key()
    
    # Return both keys
    return private_key, public_key


def serialize_keys(private_key, public_key):
    """Serialize keys to PEM format"""
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem


def encrypt_message(message, public_key):
    """Encrypt a message with the public key"""
    # Convert string message to bytes
    message_bytes = message.encode('utf-8')
    
    # Encrypt the message
    ciphertext = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Return base64 encoded ciphertext for easier handling
    return base64.b64encode(ciphertext).decode('utf-8')


def decrypt_message(encrypted_message, private_key):
    """Decrypt a message with the private key"""
    # Decode the base64 encoded ciphertext
    ciphertext = base64.b64decode(encrypted_message)
    
    # Decrypt the message
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Return the decrypted message as string
    return plaintext.decode('utf-8')


def load_private_key(private_pem):
    """Load a private key from PEM format"""
    return serialization.load_pem_private_key(
        private_pem,
        password=None
    )


def load_public_key(public_pem):
    """Load a public key from PEM format"""
    return serialization.load_pem_public_key(
        public_pem
    )


# Example usage
if __name__ == "__main__":
    # Generate key pair
    private_key, public_key = generate_key_pair()
    print("Key pair generated")
    
    # Save keys to PEM format (this would typically be saved to files)
    private_pem, public_pem = serialize_keys(private_key, public_key)
    print("Private key:\n", private_pem.decode('utf-8'))
    print("Public key:\n", public_pem.decode('utf-8'))
    
    # Original message
    original_message = "This is a secret message for asymmetric encryption demonstration."
    print(f"\nOriginal message: {original_message}")
    
    # Encrypt the message using the public key
    encrypted_message = encrypt_message(original_message, public_key)
    print(f"\nEncrypted message: {encrypted_message}")
    
    # Decrypt the message using the private key
    decrypted_message = decrypt_message(encrypted_message, private_key)
    print(f"\nDecrypted message: {decrypted_message}")
    
    # Demonstration of key serialization and loading
    print("\nDemonstrating key serialization and loading...")
    
    # Load the keys from PEM format
    loaded_private_key = load_private_key(private_pem)
    loaded_public_key = load_public_key(public_pem)
    
    # Encrypt with the loaded public key
    encrypted_message2 = encrypt_message(original_message, loaded_public_key)
    print(f"Re-encrypted message: {encrypted_message2}")
    
    # Decrypt with the loaded private key
    decrypted_message2 = decrypt_message(encrypted_message2, loaded_private_key)
    print(f"Re-decrypted message: {decrypted_message2}")
