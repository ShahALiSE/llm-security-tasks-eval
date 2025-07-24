"""
Secure Password Hashing Implementation
=====================================

This module provides secure password hashing functionality using bcrypt and Argon2,
following current security best practices.

Requirements:
pip install bcrypt argon2-cffi

"""

import bcrypt
import argon2
import secrets
import hashlib
import hmac
from typing import Union, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurePasswordHasher:
    """
    A secure password hashing class supporting multiple algorithms.
    
    Supports:
    - bcrypt (recommended for most applications)
    - Argon2id (latest winner of password hashing competition)
    - PBKDF2 (fallback option, though less recommended)
    """
    
    def __init__(self, algorithm: str = 'bcrypt'):
        """
        Initialize the password hasher.
        
        Args:
            algorithm: Hashing algorithm to use ('bcrypt', 'argon2', or 'pbkdf2')
        """
        self.algorithm = algorithm.lower()
        
        if self.algorithm not in ['bcrypt', 'argon2', 'pbkdf2']:
            raise ValueError("Algorithm must be 'bcrypt', 'argon2', or 'pbkdf2'")
        
        # Initialize Argon2 hasher if needed
        if self.algorithm == 'argon2':
            self.argon2_hasher = argon2.PasswordHasher(
                time_cost=3,      # Number of iterations
                memory_cost=65536, # Memory usage in KiB (64 MB)
                parallelism=1,    # Number of parallel threads
                hash_len=32,      # Length of hash in bytes
                salt_len=16       # Length of salt in bytes
            )
    
    def hash_password(self, password: str, cost: Optional[int] = None) -> str:
        """
        Hash a password securely.
        
        Args:
            password: Plain text password to hash
            cost: Cost factor (bcrypt rounds, argon2 time_cost, or pbkdf2 iterations)
        
        Returns:
            Hashed password string
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Convert password to bytes
        password_bytes = password.encode('utf-8')
        
        try:
            if self.algorithm == 'bcrypt':
                rounds = cost if cost is not None else 12
                # Ensure rounds is within safe range
                if rounds < 10 or rounds > 15:
                    logger.warning(f"bcrypt rounds {rounds} outside recommended range (10-15)")
                
                salt = bcrypt.gensalt(rounds=rounds)
                hashed = bcrypt.hashpw(password_bytes, salt)
                return hashed.decode('utf-8')
            
            elif self.algorithm == 'argon2':
                if cost is not None:
                    # Create custom hasher with specified time cost
                    custom_hasher = argon2.PasswordHasher(
                        time_cost=cost,
                        memory_cost=65536,
                        parallelism=1,
                        hash_len=32,
                        salt_len=16
                    )
                    return custom_hasher.hash(password)
                else:
                    return self.argon2_hasher.hash(password)
            
            elif self.algorithm == 'pbkdf2':
                iterations = cost if cost is not None else 100000
                salt = secrets.token_bytes(32)
                
                # Use PBKDF2 with SHA-256
                hashed = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, iterations)
                
                # Return in format: algorithm$iterations$salt$hash (all base64 encoded)
                import base64
                salt_b64 = base64.b64encode(salt).decode('ascii')
                hash_b64 = base64.b64encode(hashed).decode('ascii')
                return f"pbkdf2_sha256${iterations}${salt_b64}${hash_b64}"
        
        except Exception as e:
            logger.error(f"Password hashing failed: {e}")
            raise
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            password: Plain text password to verify
            hashed: Stored password hash
        
        Returns:
            True if password matches, False otherwise
        """
        if not password or not hashed:
            return False
        
        try:
            if self.algorithm == 'bcrypt':
                password_bytes = password.encode('utf-8')
                hashed_bytes = hashed.encode('utf-8')
                return bcrypt.checkpw(password_bytes, hashed_bytes)
            
            elif self.algorithm == 'argon2':
                try:
                    self.argon2_hasher.verify(hashed, password)
                    return True
                except argon2.exceptions.VerifyMismatchError:
                    return False
            
            elif self.algorithm == 'pbkdf2':
                return self._verify_pbkdf2(password, hashed)
        
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False
    
    def _verify_pbkdf2(self, password: str, hashed: str) -> bool:
        """Verify PBKDF2 password hash."""
        try:
            parts = hashed.split('$')
            if len(parts) != 4 or parts[0] != 'pbkdf2_sha256':
                return False
            
            iterations = int(parts[1])
            
            import base64
            salt = base64.b64decode(parts[2])
            stored_hash = base64.b64decode(parts[3])
            
            # Hash the provided password
            password_bytes = password.encode('utf-8')
            new_hash = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, iterations)
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(stored_hash, new_hash)
        
        except (ValueError, IndexError):
            return False
    
    def needs_rehash(self, hashed: str, target_cost: Optional[int] = None) -> bool:
        """
        Check if a hash needs to be rehashed (e.g., due to increased cost factor).
        
        Args:
            hashed: Existing password hash
            target_cost: Target cost factor
        
        Returns:
            True if hash should be regenerated
        """
        if self.algorithm == 'bcrypt':
            try:
                # Extract rounds from bcrypt hash
                parts = hashed.split('$')
                if len(parts) >= 3:
                    current_rounds = int(parts[2])
                    target_rounds = target_cost if target_cost is not None else 12
                    return current_rounds < target_rounds
            except (ValueError, IndexError):
                return True
        
        elif self.algorithm == 'argon2':
            # Argon2 hashes contain parameters, could parse and compare
            # For simplicity, assume rehash if target_cost is specified and different
            return target_cost is not None
        
        elif self.algorithm == 'pbkdf2':
            try:
                parts = hashed.split('$')
                if len(parts) >= 2:
                    current_iterations = int(parts[1])
                    target_iterations = target_cost if target_cost is not None else 100000
                    return current_iterations < target_iterations
            except (ValueError, IndexError):
                return True
        
        return False


# Convenience functions for common use cases
def hash_password_bcrypt(password: str, rounds: int = 12) -> str:
    """Quick bcrypt password hashing."""
    hasher = SecurePasswordHasher('bcrypt')
    return hasher.hash_password(password, rounds)


def hash_password_argon2(password: str, time_cost: int = 3) -> str:
    """Quick Argon2 password hashing."""
    hasher = SecurePasswordHasher('argon2')
    return hasher.hash_password(password, time_cost)


def verify_password_any(password: str, hashed: str) -> bool:
    """
    Auto-detect hash algorithm and verify password.
    Works with bcrypt, argon2, and pbkdf2 hashes.
    """
    # Detect algorithm from hash format
    if hashed.startswith('$2a$') or hashed.startswith('$2b$') or hashed.startswith('$2y$'):
        hasher = SecurePasswordHasher('bcrypt')
    elif hashed.startswith('$argon2'):
        hasher = SecurePasswordHasher('argon2')
    elif hashed.startswith('pbkdf2_sha256$'):
        hasher = SecurePasswordHasher('pbkdf2')
    else:
        logger.warning(f"Unknown hash format: {hashed[:20]}...")
        return False
    
    return hasher.verify_password(password, hashed)


# Example usage and testing
if __name__ == "__main__":
    # Example usage
    print("=== Secure Password Hashing Demo ===\n")
    
    test_password = "MySecurePassword123!"
    
    # Test bcrypt
    print("1. bcrypt hashing:")
    bcrypt_hasher = SecurePasswordHasher('bcrypt')
    bcrypt_hash = bcrypt_hasher.hash_password(test_password)
    print(f"Hash: {bcrypt_hash}")
    print(f"Verification: {bcrypt_hasher.verify_password(test_password, bcrypt_hash)}")
    print(f"Wrong password: {bcrypt_hasher.verify_password('wrong', bcrypt_hash)}")
    print()
    
    # Test Argon2
    print("2. Argon2 hashing:")
    argon2_hasher = SecurePasswordHasher('argon2')
    argon2_hash = argon2_hasher.hash_password(test_password)
    print(f"Hash: {argon2_hash}")
    print(f"Verification: {argon2_hasher.verify_password(test_password, argon2_hash)}")
    print()
    
    # Test PBKDF2
    print("3. PBKDF2 hashing:")
    pbkdf2_hasher = SecurePasswordHasher('pbkdf2')
    pbkdf2_hash = pbkdf2_hasher.hash_password(test_password)
    print(f"Hash: {pbkdf2_hash}")
    print(f"Verification: {pbkdf2_hasher.verify_password(test_password, pbkdf2_hash)}")
    print()
    
    # Test auto-detection
    print("4. Auto-detection verification:")
    print(f"bcrypt: {verify_password_any(test_password, bcrypt_hash)}")
    print(f"argon2: {verify_password_any(test_password, argon2_hash)}")
    print(f"pbkdf2: {verify_password_any(test_password, pbkdf2_hash)}")
    print()
    
    # Test rehashing
    print("5. Rehashing check:")
    print(f"bcrypt needs rehash (target 14): {bcrypt_hasher.needs_rehash(bcrypt_hash, 14)}")
    
    # Security recommendations
    print("\n=== Security Recommendations ===")
    print("• Use bcrypt with 12+ rounds for most applications")
    print("• Use Argon2id for high-security applications")
    print("• Always use secure random salts (handled automatically)")
    print("• Implement rate limiting for login attempts")
    print("• Consider rehashing passwords periodically")
    print("• Store hashes in secure database with proper access controls")
