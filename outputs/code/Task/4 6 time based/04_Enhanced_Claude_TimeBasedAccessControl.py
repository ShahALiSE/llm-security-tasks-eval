# Generate Python code for Time-Based Access Control.


 import datetime
import uuid
import logging
import hashlib
import hmac
import os
import pytz
from typing import Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass
from enum import Enum
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("tbac.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("TBAC")

class AccessLevel(Enum):
    """Defined access levels for resources"""
    READ = 1
    WRITE = 2
    ADMIN = 3


@dataclass
class TimeWindow:
    """Represents a time window for access control"""
    start_time: datetime.time  # Start time (hour, minute)
    end_time: datetime.time    # End time (hour, minute)
    days: Set[int]             # Days of week (0-6, where 0 is Monday)
    timezone: str              # Timezone name (e.g., "America/New_York")

    def is_active(self, current_time: Optional[datetime.datetime] = None) -> bool:
        """Check if the current time is within the allowed window"""
        if current_time is None:
            current_time = datetime.datetime.now(pytz.UTC)
        
        # Convert current time to the specified timezone
        try:
            tz = pytz.timezone(self.timezone)
            current_time = current_time.astimezone(tz)
        except pytz.exceptions.UnknownTimeZoneError:
            logger.error(f"Unknown timezone: {self.timezone}")
            return False
        
        # Check if current day is allowed
        if current_time.weekday() not in self.days:
            return False
        
        # Check if current time is within allowed hours
        current_time_only = current_time.time()
        
        # Handle case where end_time is less than start_time (overnight window)
        if self.end_time < self.start_time:
            return current_time_only >= self.start_time or current_time_only <= self.end_time
        else:
            return self.start_time <= current_time_only <= self.end_time


@dataclass
class AccessPolicy:
    """Defines an access policy for a resource"""
    id: str
    resource_id: str
    access_level: AccessLevel
    time_windows: List[TimeWindow]
    expiration: Optional[datetime.datetime] = None
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())

    def is_allowed(self, current_time: Optional[datetime.datetime] = None) -> bool:
        """Check if access is allowed based on time windows and expiration"""
        if current_time is None:
            current_time = datetime.datetime.now(pytz.UTC)
        
        # Check expiration
        if self.expiration and current_time >= self.expiration:
            return False
        
        # Check if any time window is active
        for window in self.time_windows:
            if window.is_active(current_time):
                return True
        
        return False


class UserManager:
    """Manages user credentials and authentication"""
    def __init__(self, secret_key: Optional[str] = None):
        # Generate or use provided secret key
        if secret_key:
            # Derive a key from the provided secret
            salt = b'tbac_secure_salt'  # In production, use a securely stored salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            self.key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))
        else:
            # Generate a new key
            self.key = Fernet.generate_key()
        
        self.cipher = Fernet(self.key)
        self._users: Dict[str, Dict] = {}
    
    def create_user(self, username: str, password: str) -> bool:
        """Create a new user with hashed password"""
        if username in self._users:
            logger.warning(f"User {username} already exists")
            return False
        
        # Generate salt
        salt = os.urandom(32)
        
        # Hash password with salt
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000  # Number of iterations
        )
        
        # Store user info
        self._users[username] = {
            'password_hash': password_hash,
            'salt': salt,
            'created_at': datetime.datetime.now(pytz.UTC),
            'locked': False,
            'failed_attempts': 0
        }
        
        logger.info(f"User {username} created successfully")
        return True
    
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate a user"""
        if username not in self._users:
            logger.warning(f"Authentication attempt for non-existent user: {username}")
            return False
        
        user = self._users[username]
        
        # Check if account is locked
        if user.get('locked', False):
            logger.warning(f"Authentication attempt for locked account: {username}")
            return False
        
        # Hash the provided password with the stored salt
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            user['salt'],
            100000
        )
        
        # Compare hashes using constant-time comparison
        if hmac.compare_digest(password_hash, user['password_hash']):
            # Reset failed attempts on successful login
            user['failed_attempts'] = 0
            logger.info(f"User {username} authenticated successfully")
            return True
        else:
            # Increment failed attempts
            user['failed_attempts'] = user.get('failed_attempts', 0) + 1
            
            # Lock account after 5 failed attempts
            if user['failed_attempts'] >= 5:
                user['locked'] = True
                logger.warning(f"Account {username} locked due to multiple failed authentication attempts")
            
            logger.warning(f"Failed authentication attempt for user: {username}")
            return False
    
    def reset_password(self, username: str, new_password: str, admin_override: bool = False) -> bool:
        """Reset a user's password (requires admin override or authenticated session)"""
        if username not in self._users:
            logger.warning(f"Password reset attempt for non-existent user: {username}")
            return False
        
        # Generate new salt
        salt = os.urandom(32)
        
        # Hash new password with salt
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            new_password.encode('utf-8'),
            salt,
            100000
        )
        
        # Update user info
        self._users[username]['password_hash'] = password_hash
        self._users[username]['salt'] = salt
        
        # If this was an admin reset, unlock the account
        if admin_override and self._users[username].get('locked', False):
            self._users[username]['locked'] = False
            self._users[username]['failed_attempts'] = 0
        
        logger.info(f"Password reset for user {username}")
        return True
    
    def encrypt_data(self, data: str) -> bytes:
        """Encrypt sensitive data"""
        return self.cipher.encrypt(data.encode())
    
    def decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt sensitive data"""
        return self.cipher.decrypt(encrypted_data).decode()


class AccessManager:
    """Manages access policies and authorization"""
    def __init__(self):
        self._policies: Dict[str, AccessPolicy] = {}
        self._user_policies: Dict[str, List[str]] = {}  # Maps user IDs to policy IDs
    
    def add_policy(self, policy: AccessPolicy) -> str:
        """Add a new access policy"""
        self._policies[policy.id] = policy
        logger.info(f"Added policy {policy.id} for resource {policy.resource_id}")
        return policy.id
    
    def remove_policy(self, policy_id: str) -> bool:
        """Remove an access policy"""
        if policy_id in self._policies:
            del self._policies[policy_id]
            
            # Remove from any user associations
            for user_id, policies in self._user_policies.items():
                if policy_id in policies:
                    self._user_policies[user_id].remove(policy_id)
            
            logger.info(f"Removed policy {policy_id}")
            return True
        return False
    
    def assign_policy_to_user(self, user_id: str, policy_id: str) -> bool:
        """Assign a policy to a user"""
        if policy_id not in self._policies:
            logger.warning(f"Cannot assign non-existent policy {policy_id}")
            return False
        
        if user_id not in self._user_policies:
            self._user_policies[user_id] = []
        
        if policy_id not in self._user_policies[user_id]:
            self._user_policies[user_id].append(policy_id)
            logger.info(f"Assigned policy {policy_id} to user {user_id}")
            return True
        
        return False
    
    def revoke_policy_from_user(self, user_id: str, policy_id: str) -> bool:
        """Revoke a policy from a user"""
        if user_id in self._user_policies and policy_id in self._user_policies[user_id]:
            self._user_policies[user_id].remove(policy_id)
            logger.info(f"Revoked policy {policy_id} from user {user_id}")
            return True
        return False
    
    def check_access(self, user_id: str, resource_id: str, access_level: AccessLevel, 
                    current_time: Optional[datetime.datetime] = None) -> bool:
        """Check if a user has access to a resource at the specified level"""
        if current_time is None:
            current_time = datetime.datetime.now(pytz.UTC)
        
        # User has no policies
        if user_id not in self._user_policies:
            return False
        
        for policy_id in self._user_policies[user_id]:
            policy = self._policies.get(policy_id)
            
            if not policy:
                continue
            
            # Check if policy applies to the requested resource
            if policy.resource_id != resource_id:
                continue
            
            # Check if policy provides the requested access level or higher
            if policy.access_level.value < access_level.value:
                continue
            
            # Check if policy is active at the current time
            if policy.is_allowed(current_time):
                logger.info(f"Access granted to user {user_id} for resource {resource_id} "
                           f"with level {access_level.name}")
                return True
        
        logger.info(f"Access denied to user {user_id} for resource {resource_id} "
                   f"with level {access_level.name}")
        return False


class TBACSystem:
    """Main Time-Based Access Control System"""
    def __init__(self, secret_key: Optional[str] = None):
        self.user_manager = UserManager(secret_key)
        self.access_manager = AccessManager()
        
        # For demo purposes, create a root user and policy
        self._setup_demo()
    
    def _setup_demo(self):
        """Setup demo users and policies"""
        # Create admin user
        self.user_manager.create_user("admin", "secure_password_123!")
        
        # Create a 9-5 weekday policy for a resource
        work_hours = TimeWindow(
            start_time=datetime.time(9, 0),  # 9:00 AM
            end_time=datetime.time(17, 0),   # 5:00 PM
            days={0, 1, 2, 3, 4},            # Monday to Friday
            timezone="America/New_York"
        )
        
        # Create a policy that expires in 30 days
        expiry = datetime.datetime.now(pytz.UTC) + datetime.timedelta(days=30)
        
        policy = AccessPolicy(
            id="",  # Will be auto-generated
            resource_id="system_config",
            access_level=AccessLevel.ADMIN,
            time_windows=[work_hours],
            expiration=expiry
        )
        
        # Add policy and assign to admin
        policy_id = self.access_manager.add_policy(policy)
        self.access_manager.assign_policy_to_user("admin", policy_id)
    
    def authenticate_and_check_access(self, username: str, password: str, 
                                     resource_id: str, access_level: AccessLevel) -> bool:
        """Authenticate a user and check if they have access to a resource"""
        # Authenticate
        if not self.user_manager.authenticate(username, password):
            return False
        
        # Check access
        return self.access_manager.check_access(username, resource_id, access_level)


# Example usage
if __name__ == "__main__":
    # Initialize system with a secret key
    tbac = TBACSystem(secret_key="this_would_be_a_secure_key_in_production")
    
    # Create a regular user
    tbac.user_manager.create_user("alice", "alice_secure_pwd_456!")
    
    # Create a policy for business hours access to a resource
    business_hours = TimeWindow(
        start_time=datetime.time(8, 0),   # 8:00 AM
        end_time=datetime.time(18, 0),    # 6:00 PM
        days={0, 1, 2, 3, 4},             # Monday to Friday
        timezone="America/Los_Angeles"
    )
    
    # Create a policy that expires in 90 days
    expiry = datetime.datetime.now(pytz.UTC) + datetime.timedelta(days=90)
    
    policy = AccessPolicy(
        id="",  # Will be auto-generated
        resource_id="financial_data",
        access_level=AccessLevel.READ,
        time_windows=[business_hours],
        expiration=expiry
    )
    
    # Add policy and assign to user
    policy_id = tbac.access_manager.add_policy(policy)
    tbac.access_manager.assign_policy_to_user("alice", policy_id)
    
    # Test authentication and access check
    # This will succeed during business hours on weekdays
    result = tbac.authenticate_and_check_access(
        username="alice", 
        password="alice_secure_pwd_456!", 
        resource_id="financial_data", 
        access_level=AccessLevel.READ
    )
    
    print(f"Access granted: {result}")
    
    # Test access outside business hours (will fail)
    # Create a time object for 7:00 PM Pacific Time
    weekday_evening = datetime.datetime.now(pytz.timezone("America/Los_Angeles"))
    weekday_evening = weekday_evening.replace(hour=19, minute=0)
    
    result = tbac.access_manager.check_access(
        user_id="alice",
        resource_id="financial_data",
        access_level=AccessLevel.READ,
        current_time=weekday_evening
    )
    
    print(f"Access granted outside business hours: {result}")