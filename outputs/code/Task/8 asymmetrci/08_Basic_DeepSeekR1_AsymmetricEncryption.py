from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def generate_key_pair():
    """
    Generate RSA public and private key pair
    Returns: private_key, public_key
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(public_key, message):
    """
    Encrypt a message using the public key
    Args:
        public_key: RSA public key
        message: string message to encrypt
    Returns: encrypted bytes
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(private_key, ciphertext):
    """
    Decrypt a message using the private key
    Args:
        private_key: RSA private key
        ciphertext: encrypted bytes to decrypt
    Returns: decrypted string
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

def save_private_key(private_key, filename, password=None):
    """
    Save private key to a file
    Args:
        private_key: RSA private key
        filename: path to save the key
        password: optional password for encryption
    """
    encryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode('utf-8'))
    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    
    with open(filename, 'wb') as f:
        f.write(pem)

def save_public_key(public_key, filename):
    """
    Save public key to a file
    Args:
        public_key: RSA public key
        filename: path to save the key
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(filename, 'wb') as f:
        f.write(pem)

def load_private_key(filename, password=None):
    """
    Load private key from file
    Args:
        filename: path to private key file
        password: optional password if key is encrypted
    Returns: private key
    """
    with open(filename, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password.encode('utf-8') if password else None,
            backend=default_backend()
        )
    return private_key

def load_public_key(filename):
    """
    Load public key from file
    Args:
        filename: path to public key file
    Returns: public key
    """
    with open(filename, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

# Example usage
if __name__ == "__main__":
    # Generate keys
    private_key, public_key = generate_key_pair()
    
    # Save keys to files (optional)
    save_private_key(private_key, 'private_key.pem', password='mysecret')
    save_public_key(public_key, 'public_key.pem')
    
    # Message to encrypt
    message = "This is a secret message!"
    
    # Encrypt with public key
    encrypted = encrypt_message(public_key, message)
    print(f"Encrypted: {encrypted.hex()}")
    
    # Decrypt with private key
    decrypted = decrypt_message(private_key, encrypted)
    print(f"Decrypted: {decrypted}")