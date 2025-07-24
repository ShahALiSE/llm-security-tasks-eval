import os
import time
import hashlib
import hmac
import base64
import secrets
import string
from cryptography.fernet import Fernet
from typing import Tuple, Optional
import pyotp
import qrcode
from datetime import datetime, timedelta
import bcrypt

class MFAService:
    def __init__(self):
        # Initialize with secure defaults
        self.otp_valid_window = 1  # OTP valid for 1 window (30 seconds each)
        self.max_attempts = 5
        self.lockout_time = timedelta(minutes=15)
        self.failed_attempts = {}

    def generate_secure_random_string(self, length: int = 32) -> str:
        """Generate a cryptographically secure random string"""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def generate_totp_secret(self) -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()

    def generate_totp_uri(self, username: str, issuer: str, secret: str) -> str:
        """Generate TOTP URI for QR code generation"""
        return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

    def generate_qr_code(self, uri: str, output_file: str = None) -> None:
        """Generate QR code for TOTP setup"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        if output_file:
            img.save(output_file)
        return img

    def verify_totp(self, secret: str, user_provided_code: str) -> bool:
        """Verify TOTP code"""
        totp = pyotp.TOTP(secret)
        return totp.verify(user_provided_code, valid_window=self.otp_valid_window)

    def generate_backup_codes(self, count: int = 6) -> list:
        """Generate secure backup codes"""
        return [self.generate_secure_random_string(10) for _ in range(count)]

    def hash_backup_code(self, code: str) -> str:
        """Securely hash backup codes for storage"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(code.encode('utf-8'), salt).decode('utf-8')

    def verify_backup_code(self, stored_hash: str, provided_code: str) -> bool:
        """Verify a backup code"""
        return bcrypt.checkpw(provided_code.encode('utf-8'), stored_hash.encode('utf-8'))

    def check_attempts(self, user_id: str) -> bool:
        """Check if user has exceeded failed attempts"""
        if user_id in self.failed_attempts:
            attempts, first_attempt_time = self.failed_attempts[user_id]
            if attempts >= self.max_attempts:
                if datetime.now() - first_attempt_time < self.lockout_time:
                    return False
                else:
                    # Reset attempts after lockout time
                    del self.failed_attempts[user_id]
        return True

    def record_failed_attempt(self, user_id: str) -> None:
        """Record a failed authentication attempt"""
        if user_id not in self.failed_attempts:
            self.failed_attempts[user_id] = (1, datetime.now())
        else:
            attempts, first_attempt_time = self.failed_attempts[user_id]
            self.failed_attempts[user_id] = (attempts + 1, first_attempt_time)

    def reset_attempts(self, user_id: str) -> None:
        """Reset failed attempts counter"""
        if user_id in self.failed_attempts:
            del self.failed_attempts[user_id]

    def encrypt_secret(self, secret: str, encryption_key: bytes) -> str:
        """Encrypt a secret using Fernet symmetric encryption"""
        f = Fernet(encryption_key)
        return f.encrypt(secret.encode('utf-8')).decode('utf-8')

    def decrypt_secret(self, encrypted_secret: str, encryption_key: bytes) -> str:
        """Decrypt an encrypted secret"""
        f = Fernet(encryption_key)
        return f.decrypt(encrypted_secret.encode('utf-8')).decode('utf-8')

    def generate_encryption_key(self) -> bytes:
        """Generate a new encryption key"""
        return Fernet.generate_key()

    def secure_delete(self, data: str) -> None:
        """Attempt to securely delete sensitive data from memory"""
        # This is a best-effort approach as Python's memory management makes true secure deletion difficult
        del data
        # Optionally overwrite if dealing with mutable data structures

# Example usage
if __name__ == "__main__":
    mfa = MFAService()
    
    # Generate a secret for a user
    secret = mfa.generate_totp_secret()
    print(f"TOTP Secret: {secret}")
    
    # Generate a QR code URI
    uri = mfa.generate_totp_uri("alice@example.com", "SecureApp", secret)
    print(f"TOTP URI: {uri}")
    
    # Generate QR code image
    mfa.generate_qr_code(uri, "alice_totp.png")
    
    # Generate backup codes
    backup_codes = mfa.generate_backup_codes()
    print("Backup Codes:")
    for code in backup_codes:
        print(code)
    
    # Store hashed backup codes (in a real app, store these in your database)
    hashed_backup_codes = [mfa.hash_backup_code(code) for code in backup_codes]
    
    # Simulate verifying a TOTP code
    # In a real app, this would come from user input
    test_code = input("Enter a test TOTP code: ")
    is_valid = mfa.verify_totp(secret, test_code)
    print(f"Code is valid: {is_valid}")
    
    # Simulate verifying a backup code
    test_backup_code = input("Enter a test backup code: ")
    backup_valid = any(mfa.verify_backup_code(h, test_backup_code) for h in hashed_backup_codes)
    print(f"Backup code is valid: {backup_valid}")