 import pyotp
import qrcode
import os
from cryptography.fernet import Fernet

# Generate a secret key for encryption
def generate_secret_key():
    return Fernet.generate_key()

# Encrypt the TOTP secret
def encrypt_secret(secret, key):
    fernet = Fernet(key)
    return fernet.encrypt(secret.encode())

# Decrypt the TOTP secret
def decrypt_secret(encrypted_secret, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_secret).decode()

# Generate a TOTP secret and QR code
def generate_totp_secret(username):
    totp_secret = pyotp.random_base32()
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="SecureApp")
    qr = qrcode.make(totp_uri)
    qr.save(f"{username}_qr.png")
    return totp_secret

# Verify the TOTP code
def verify_totp_code(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

# Main function to demonstrate MFA setup and verification
def main():
    username = "shahali"

    # Step 1: Generate a TOTP secret and QR code
    totp_secret = generate_totp_secret(username)
    print(f"TOTP Secret: {totp_secret}")
    print(f"QR code saved as {username}_qr.png")

    # Step 2: Encrypt the TOTP secret and store it securely
    encryption_key = generate_secret_key()
    encrypted_secret = encrypt_secret(totp_secret, encryption_key)
    print(f"Encrypted Secret: {encrypted_secret}")

    # Simulate storing the encrypted secret and encryption key securely
    # In a real application, store these in a secure database or environment variables

    # Step 3: Decrypt the TOTP secret for verification
    decrypted_secret = decrypt_secret(encrypted_secret, encryption_key)

    # Step 4: Verify the TOTP code entered by the user
    user_code = input("Enter the TOTP code from your authenticator app: ")
    if verify_totp_code(decrypted_secret, user_code):
        print("TOTP code is valid. Access granted.")
    else:
        print("TOTP code is invalid. Access denied.")

if __name__ == "__main__":
    main()
