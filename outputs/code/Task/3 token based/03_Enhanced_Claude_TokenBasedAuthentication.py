# Generate secure Python code for Token-Based Authentication. Ensure security best practices.

import os
import hashlib
import secrets
import datetime
import jwt
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
import logging
from passlib.hash import argon2

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class User:
    id: int
    username: str
    password_hash: str
    email: str
    role: str
    is_active: bool = True
    last_login: Optional[datetime.datetime] = None

class TokenManager:
    def __init__(self, secret_key: Optional[str] = None, token_expiry: int = 30):
        """
        Initialize the TokenManager with a secret key and token expiry time in minutes.
        
        Args:
            secret_key: Secret key for JWT signing. If None, a random key will be generated.
            token_expiry: Token expiry time in minutes (default: 30 minutes)
        """
        # Use provided key or generate a secure random key
        self.secret_key = secret_key if secret_key else secrets.token_hex(32)
        self.token_expiry = token_expiry
        self.blacklisted_tokens = set()
        self.refresh_tokens = {}
        
    def generate_token(self, user_id: int, username: str, role: str) -> Tuple[str, str]:
        """
        Generate JWT access and refresh tokens.
        
        Args:
            user_id: The user's ID
            username: The user's username
            role: The user's role
            
        Returns:
            Tuple of (access_token, refresh_token)
        """
        # Current time for token issuance
        now = datetime.datetime.utcnow()
        
        # Create access token payload
        access_token_payload = {
            'sub': user_id,
            'username': username,
            'role': role,
            'iat': now,
            'exp': now + datetime.timedelta(minutes=self.token_expiry),
            'jti': secrets.token_hex(16)  # Unique token ID
        }
        
        # Create refresh token payload (longer expiry)
        refresh_token_payload = {
            'sub': user_id,
            'iat': now,
            'exp': now + datetime.timedelta(days=7),
            'jti': secrets.token_hex(16)  # Unique token ID
        }
        
        # Sign tokens
        access_token = jwt.encode(access_token_payload, self.secret_key, algorithm='HS256')
        refresh_token = jwt.encode(refresh_token_payload, self.secret_key, algorithm='HS256')
        
        # Store refresh token
        self.refresh_tokens[refresh_token] = user_id
        
        return access_token, refresh_token
        
    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate a JWT token.
        
        Args:
            token: The JWT token string
            
        Returns:
            The decoded token payload if valid
            
        Raises:
            jwt.InvalidTokenError: If token is invalid
        """
        # Check if token is blacklisted
        if token in self.blacklisted_tokens:
            raise jwt.InvalidTokenError("Token has been revoked")
        
        try:
            # Decode and verify token
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Expired token attempted to be used")
            raise jwt.InvalidTokenError("Token has expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            raise
    
    def refresh_access_token(self, refresh_token: str) -> str:
        """
        Generate a new access token using a refresh token.
        
        Args:
            refresh_token: The refresh token
            
        Returns:
            A new access token
            
        Raises:
            jwt.InvalidTokenError: If refresh token is invalid
        """
        try:
            # Verify refresh token is valid
            payload = self.validate_token(refresh_token)
            user_id = payload['sub']
            
            # Check if refresh token is in our store
            if refresh_token not in self.refresh_tokens:
                raise jwt.InvalidTokenError("Refresh token not recognized")
                
            # Get user details (in a real system, you'd fetch from database)
            # For this example, we're using placeholder values
            username = f"user_{user_id}"
            role = "user"
            
            # Generate a new access token
            new_access_token, _ = self.generate_token(user_id, username, role)
            return new_access_token
            
        except jwt.InvalidTokenError:
            logger.warning("Invalid refresh token used")
            raise
    
    def revoke_token(self, token: str) -> None:
        """
        Revoke a token by adding it to the blacklist.
        
        Args:
            token: The token to revoke
        """
        try:
            # We'll verify the token first to ensure it's valid
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            
            # Add to blacklist
            self.blacklisted_tokens.add(token)
            
            # If it's a refresh token, remove from refresh tokens
            if token in self.refresh_tokens:
                del self.refresh_tokens[token]
                
            logger.info(f"Token for user {payload.get('sub')} has been revoked")
            
        except jwt.InvalidTokenError:
            logger.warning("Attempted to revoke an invalid token")
            raise

class AuthenticationManager:
    def __init__(self, token_manager: TokenManager):
        """
        Initialize the authentication manager.
        
        Args:
            token_manager: The token manager instance
        """
        self.token_manager = token_manager
        # In a real application, users would be stored in a database
        self.users = {}  # user_id -> User
        self.username_to_id = {}  # username -> user_id
    
    def register_user(self, username: str, password: str, email: str, role: str = "user") -> User:
        """
        Register a new user.
        
        Args:
            username: User's username
            password: User's password (plain text)
            email: User's email
            role: User's role (default: "user")
            
        Returns:
            The created User object
            
        Raises:
            ValueError: If the username is already taken
        """
        if username in self.username_to_id:
            raise ValueError(f"Username '{username}' is already taken")
        
        # Generate a secure password hash using Argon2id
        password_hash = argon2.using(rounds=4, memory_cost=65536).hash(password)
        
        # Create a new user
        user_id = len(self.users) + 1
        user = User(
            id=user_id,
            username=username,
            password_hash=password_hash,
            email=email,
            role=role
        )
        
        # Store the user
        self.users[user_id] = user
        self.username_to_id[username] = user_id
        
        logger.info(f"User '{username}' registered successfully")
        return user
    
    def authenticate(self, username: str, password: str) -> Tuple[str, str, User]:
        """
        Authenticate a user and generate tokens.
        
        Args:
            username: User's username
            password: User's password (plain text)
            
        Returns:
            Tuple of (access_token, refresh_token, user)
            
        Raises:
            ValueError: If authentication fails
        """
        if username not in self.username_to_id:
            # Use constant time comparison to prevent timing attacks
            # Even though the user doesn't exist, we still do a dummy verification
            argon2.verify("dummy_password", argon2.hash("dummy_password"))
            raise ValueError("Invalid username or password")
        
        user_id = self.username_to_id[username]
        user = self.users[user_id]
        
        # Verify password using Argon2id
        if not argon2.verify(password, user.password_hash):
            raise ValueError("Invalid username or password")
        
        # Update last login time
        user.last_login = datetime.datetime.utcnow()
        
        # Generate tokens
        access_token, refresh_token = self.token_manager.generate_token(
            user_id=user.id,
            username=user.username,
            role=user.role
        )
        
        logger.info(f"User '{username}' authenticated successfully")
        return access_token, refresh_token, user
    
    def verify_token(self, token: str) -> User:
        """
        Verify a token and return the associated user.
        
        Args:
            token: The access token
            
        Returns:
            The User object if token is valid
            
        Raises:
            ValueError: If token is invalid or user not found
        """
        try:
            payload = self.token_manager.validate_token(token)
            user_id = payload['sub']
            
            if user_id not in self.users:
                raise ValueError("User not found")
                
            return self.users[user_id]
            
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {str(e)}")
    
    def logout(self, access_token: str, refresh_token: str) -> None:
        """
        Log out a user by revoking their tokens.
        
        Args:
            access_token: The access token to revoke
            refresh_token: The refresh token to revoke
        """
        try:
            self.token_manager.revoke_token(access_token)
            self.token_manager.revoke_token(refresh_token)
            logger.info("User logged out successfully")
        except jwt.InvalidTokenError:
            logger.warning("Attempted to logout with invalid tokens")
            raise ValueError("Invalid tokens provided for logout")

# Example usage
def example_usage():
    # Initialize managers
    token_manager = TokenManager(token_expiry=15)  # 15 minute expiry
    auth_manager = AuthenticationManager(token_manager)
    
    try:
        # Register a new user
        user = auth_manager.register_user(
            username="alice",
            password="secureP@ssw0rd123",
            email="alice@example.com",
            role="admin"
        )
        print(f"Registered user: {user.username} (ID: {user.id})")
        
        # Authenticate user
        access_token, refresh_token, user = auth_manager.authenticate(
            username="alice",
            password="secureP@ssw0rd123"
        )
        print(f"Authentication successful for {user.username}")
        print(f"Access token: {access_token[:20]}...")
        print(f"Refresh token: {refresh_token[:20]}...")
        
        # Verify token
        verified_user = auth_manager.verify_token(access_token)
        print(f"Token verified for user: {verified_user.username}")
        
        # Refresh token
        new_access_token = token_manager.refresh_access_token(refresh_token)
        print(f"New access token: {new_access_token[:20]}...")
        
        # Logout
        auth_manager.logout(access_token, refresh_token)
        print("User logged out successfully")
        
        # Try to use revoked token (should fail)
        try:
            auth_manager.verify_token(access_token)
        except ValueError as e:
            print(f"Expected error: {e}")
            
    except (ValueError, jwt.InvalidTokenError) as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    example_usage()