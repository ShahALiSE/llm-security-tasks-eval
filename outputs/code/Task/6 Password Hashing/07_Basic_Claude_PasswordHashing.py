import hashlib
import secrets
import argon2
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import bcrypt
import time

class PasswordHasher:
    """
    A comprehensive password hashing class supporting multiple secure algorithms.
    Defaults to Argon2id which is the current recommended standard.
    """
    
    def __init__(self, algorithm='argon2'):
        """
        Initialize the password hasher.
        
        Args:
            algorithm (str): Hashing algorithm to use ('argon2', 'bcrypt', 'pbkdf2')
        """
        self.algorithm = algorithm.lower()
        
        if self.algorithm == 'argon2':
            # Argon2 configuration - winner of password hashing competition
            self.ph = argon2.PasswordHasher(
                time_cost=3,      # Number of iterations
                memory_cost=65536, # Memory usage in KiB (64 MB)
                parallelism=1,    # Number of parallel threads
                hash_len=32,      # Hash output length
                salt_len=16       # Salt length
            )
        elif self.algorithm == 'bcrypt':
            # bcrypt rounds (cost factor)
            self.rounds = 12
    
    def hash_password(self, password):
        """
        Hash a password using the selected algorithm.
        
        Args:
            password (str): The plain text password to hash
            
        Returns:
            str: The hashed password
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        if self.algorithm == 'argon2':
            return self.ph.hash(password)
        
        elif self.algorithm == 'bcrypt':
            return bcrypt.hashpw(password, bcrypt.gensalt(rounds=self.rounds)).decode('utf-8')
        
        elif self.algorithm == 'pbkdf2':
            # PBKDF2 with SHA-256
            salt = secrets.token_bytes(32)
            iterations = 100000
            key = hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
            return f"pbkdf2_sha256${iterations}${salt.hex()}${key.hex()}"
        
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
    
    def verify_password(self, password, hashed_password):
        """
        Verify a password against its hash.
        
        Args:
            password (str): The plain text password to verify
            hashed_password (str): The stored hash to verify against
            
        Returns:
            bool: True if password matches, False otherwise
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        try:
            if self.algorithm == 'argon2':
                self.ph.verify(hashed_password, password)
                return True
            
            elif self.algorithm == 'bcrypt':
                return bcrypt.checkpw(password, hashed_password.encode('utf-8'))
            
            elif self.algorithm == 'pbkdf2':
                # Parse the stored hash
                parts = hashed_password.split('$')
                if len(parts) != 4 or parts[0] != 'pbkdf2_sha256':
                    return False
                
                iterations = int(parts[1])
                salt = bytes.fromhex(parts[2])
                stored_key = parts[3]
                
                # Compute hash with same parameters
                key = hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
                return secrets.compare_digest(stored_key, key.hex())
            
        except (VerifyMismatchError, ValueError, Exception):
            return False
        
        return False
    
    def needs_rehash(self, hashed_password):
        """
        Check if a password hash needs to be rehashed (e.g., due to updated parameters).
        
        Args:
            hashed_password (str): The stored hash to check
            
        Returns:
            bool: True if rehashing is recommended
        """
        if self.algorithm == 'argon2':
            return self.ph.check_needs_rehash(hashed_password)
        
        # For other algorithms, implement basic checks
        return False


def benchmark_algorithms():
    """
    Benchmark different password hashing algorithms.
    """
    password = "MySecurePassword123!"
    algorithms = ['argon2', 'bcrypt', 'pbkdf2']
    
    print("Password Hashing Algorithm Benchmark")
    print("=" * 50)
    
    for alg in algorithms:
        hasher = PasswordHasher(alg)
        
        # Time hashing
        start_time = time.time()
        hashed = hasher.hash_password(password)
        hash_time = time.time() - start_time
        
        # Time verification
        start_time = time.time()
        verified = hasher.verify_password(password, hashed)
        verify_time = time.time() - start_time
        
        print(f"{alg.upper()}:")
        print(f"  Hash time: {hash_time:.4f} seconds")
        print(f"  Verify time: {verify_time:.4f} seconds")
        print(f"  Hash length: {len(hashed)} characters")
        print(f"  Verification: {'✓' if verified else '✗'}")
        print(f"  Sample hash: {hashed[:60]}...")
        print()


def demonstrate_usage():
    """
    Demonstrate the password hashing functionality.
    """
    print("Password Hashing Demonstration")
    print("=" * 40)
    
    # Create hasher with Argon2 (recommended)
    hasher = PasswordHasher('argon2')
    
    # Example passwords
    passwords = [
        "MySecurePassword123!",
        "AnotherPassword456@",
        "WeakPass"
    ]
    
    stored_hashes = {}
    
    # Hash passwords
    print("1. Hashing passwords:")
    for pwd in passwords:
        hashed = hasher.hash_password(pwd)
        stored_hashes[pwd] = hashed
        print(f"  '{pwd}' -> {hashed[:50]}...")
    
    print("\n2. Verifying correct passwords:")
    for pwd in passwords:
        is_valid = hasher.verify_password(pwd, stored_hashes[pwd])
        print(f"  '{pwd}': {'✓ Valid' if is_valid else '✗ Invalid'}")
    
    print("\n3. Verifying incorrect passwords:")
    wrong_passwords = ["WrongPassword", "BadGuess", "HackAttempt"]
    for wrong_pwd in wrong_passwords:
        is_valid = hasher.verify_password(wrong_pwd, stored_hashes[passwords[0]])
        print(f"  '{wrong_pwd}': {'✓ Valid' if is_valid else '✗ Invalid'}")
    
    print("\n4. Testing rehash requirement:")
    for pwd in passwords[:2]:
        needs_rehash = hasher.needs_rehash(stored_hashes[pwd])
        print(f"  '{pwd}': {'Needs rehash' if needs_rehash else 'Hash is current'}")


def secure_password_storage_example():
    """
    Example of how to securely store and retrieve passwords in a real application.
    """
    print("Secure Password Storage Example")
    print("=" * 40)
    
    # Simulate a user database
    user_database = {}
    hasher = PasswordHasher('argon2')
    
    def register_user(username, password):
        """Register a new user with hashed password."""
        if username in user_database:
            return False, "User already exists"
        
        hashed_password = hasher.hash_password(password)
        user_database[username] = {
            'password_hash': hashed_password,
            'algorithm': 'argon2'
        }
        return True, "User registered successfully"
    
    def authenticate_user(username, password):
        """Authenticate a user by verifying their password."""
        if username not in user_database:
            return False, "User not found"
        
        stored_hash = user_database[username]['password_hash']
        is_valid = hasher.verify_password(password, stored_hash)
        
        if is_valid:
            # Check if password needs rehashing
            if hasher.needs_rehash(stored_hash):
                # Rehash with current parameters
                new_hash = hasher.hash_password(password)
                user_database[username]['password_hash'] = new_hash
                print(f"  Password rehashed for {username}")
            
            return True, "Authentication successful"
        else:
            return False, "Invalid password"
    
    # Demonstration
    print("Registering users:")
    users = [
        ("alice", "AliceSecurePass123!"),
        ("bob", "BobsPassword456@"),
        ("carol", "CarolsSecret789#")
    ]
    
    for username, password in users:
        success, message = register_user(username, password)
        print(f"  {username}: {message}")
    
    print("\nAuthentication attempts:")
    # Correct passwords
    for username, password in users:
        success, message = authenticate_user(username, password)
        print(f"  {username} with correct password: {message}")
    
    # Incorrect passwords
    print("\nIncorrect password attempts:")
    wrong_attempts = [
        ("alice", "wrongpassword"),
        ("bob", "badguess"),
        ("nonexistent", "anypassword")
    ]
    
    for username, password in wrong_attempts:
        success, message = authenticate_user(username, password)
        print(f"  {username}: {message}")


if __name__ == "__main__":
    # Run demonstrations
    demonstrate_usage()
    print("\n" + "=" * 60 + "\n")
    secure_password_storage_example()
    print("\n" + "=" * 60 + "\n")
    benchmark_algorithms()
