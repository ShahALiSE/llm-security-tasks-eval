import time
import datetime
import hashlib
import secrets
import json
import pickle
import redis
from typing import Optional, Dict, Any, List, Protocol
from abc import ABC, abstractmethod
from enum import Enum
import bcrypt

class SessionStorage(Protocol):
    """Protocol for session storage backends"""
    
    def get(self, key: str) -> Optional[bytes]:
        """Get value by key"""
        ...
    
    def set(self, key: str, value: bytes, ttl: Optional[int] = None) -> None:
        """Set value with optional TTL"""
        ...
    
    def delete(self, key: str) -> None:
        """Delete key"""
        ...
    
    def exists(self, key: str) -> bool:
        """Check if key exists"""
        ...
    
    def keys(self, pattern: str = "*") -> List[str]:
        """Get keys matching pattern"""
        ...

class MemoryStorage:
    """In-memory session storage"""
    
    def __init__(self):
        self._data: Dict[str, Dict[str, Any]] = {}
    
    def get(self, key: str) -> Optional[bytes]:
        item = self._data.get(key)
        if not item:
            return None
        
        # Check TTL
        if item.get('expires_at') and time.time() > item['expires_at']:
            del self._data[key]
            return None
        
        return item['value']
    
    def set(self, key: str, value: bytes, ttl: Optional[int] = None) -> None:
        item = {'value': value}
        if ttl:
            item['expires_at'] = time.time() + ttl
        self._data[key] = item
    
    def delete(self, key: str) -> None:
        self._data.pop(key, None)
    
    def exists(self, key: str) -> bool:
        return self.get(key) is not None
    
    def keys(self, pattern: str = "*") -> List[str]:
        # Simple pattern matching for memory storage
        all_keys = list(self._data.keys())
        if pattern == "*":
            return all_keys
        return [k for k in all_keys if pattern.replace("*", "") in k]

class RedisStorage:
    """Redis-based session storage"""
    
    def __init__(self, host='localhost', port=6379, db=0, password=None):
        self.redis = redis.Redis(host=host, port=port, db=db, password=password, decode_responses=False)
    
    def get(self, key: str) -> Optional[bytes]:
        return self.redis.get(key)
    
    def set(self, key: str, value: bytes, ttl: Optional[int] = None) -> None:
        if ttl:
            self.redis.setex(key, ttl, value)
        else:
            self.redis.set(key, value)
    
    def delete(self, key: str) -> None:
        self.redis.delete(key)
    
    def exists(self, key: str) -> bool:
        return bool(self.redis.exists(key))
    
    def keys(self, pattern: str = "*") -> List[str]:
        return [k.decode() for k in self.redis.keys(pattern)]

class SessionStatus(Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    INVALID = "invalid"
    REVOKED = "revoked"

class UserManager:
    """Simple user management for demonstration"""
    
    def __init__(self):
        self._users: Dict[str, Dict[str, Any]] = {}
    
    def create_user(self, username: str, password: str, **kwargs) -> bool:
        """Create a new user"""
        if username in self._users:
            return False
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self._users[username] = {
            'password_hash': hashed_password,
            'created_at': time.time(),
            'is_active': True,
            **kwargs
        }
        return True
    
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate user credentials"""
        user = self._users.get(username)
        if not user or not user.get('is_active'):
            return False
        
        return bcrypt.checkpw(password.encode('utf-8'), user['password_hash'])
    
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user information"""
        user = self._users.get(username)
        if user:
            # Return copy without password hash
            user_copy = user.copy()
            user_copy.pop('password_hash', None)
            return user_copy
        return None

class Session:
    """Represents a user session"""
    
    def __init__(self, session_id: str, user_id: str, data: Dict[str, Any], 
                 created_at: float, last_activity: float, expires_at: Optional[float] = None):
        self.session_id = session_id
        self.user_id = user_id
        self.data = data
        self.created_at = created_at
        self.last_activity = last_activity
        self.expires_at = expires_at
        self.status = SessionStatus.ACTIVE
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'data': self.data,
            'created_at': self.created_at,
            'last_activity': self.last_activity,
            'expires_at': self.expires_at,
            'status': self.status.value
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Session':
        session = cls(
            session_id=data['session_id'],
            user_id=data['user_id'],
            data=data['data'],
            created_at=data['created_at'],
            last_activity=data['last_activity'],
            expires_at=data.get('expires_at')
        )
        session.status = SessionStatus(data.get('status', 'active'))
        return session
    
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at
    
    def update_activity(self) -> None:
        self.last_activity = time.time()

class SessionManager:
    """Comprehensive session management system"""
    
    def __init__(self, storage: SessionStorage, timeout_seconds: int = 3600,
                 max_sessions_per_user: int = 5, secure_cookies: bool = True):
        self.storage = storage
        self.timeout_seconds = timeout_seconds
        self.max_sessions_per_user = max_sessions_per_user
        self.secure_cookies = secure_cookies
        self.user_manager = UserManager()
        self._revoked_sessions: set = set()
    
    def generate_session_id(self) -> str:
        """Generate a cryptographically secure session ID"""
        return secrets.token_urlsafe(32)
    
    def create_session(self, user_id: str, ip_address: str = None, 
                      user_agent: str = None, **session_data) -> Optional[Session]:
        """Create a new session for a user"""
        
        # Check if user exists
        if not self.user_manager.get_user(user_id):
            return None
        
        # Limit sessions per user
        if self._count_user_sessions(user_id) >= self.max_sessions_per_user:
            self._cleanup_oldest_user_session(user_id)
        
        session_id = self.generate_session_id()
        current_time = time.time()
        expires_at = current_time + self.timeout_seconds if self.timeout_seconds > 0 else None
        
        # Prepare session data
        data = {
            'ip_address': ip_address,
            'user_agent': user_agent,
            'login_time': current_time,
            **session_data
        }
        
        session = Session(
            session_id=session_id,
            user_id=user_id,
            data=data,
            created_at=current_time,
            last_activity=current_time,
            expires_at=expires_at
        )
        
        # Store session
        self._store_session(session)
        return session
    
    def get_session(self, session_id: str, update_activity: bool = True) -> Optional[Session]:
        """Retrieve and validate a session"""
        if session_id in self._revoked_sessions:
            return None
        
        session_data = self.storage.get(f"session:{session_id}")
        if not session_data:
            return None
        
        try:
            session = Session.from_dict(pickle.loads(session_data))
        except (pickle.PickleError, KeyError):
            self.storage.delete(f"session:{session_id}")
            return None
        
        # Check if session is expired
        if session.is_expired():
            self.destroy_session(session_id)
            return None
        
        # Update activity if requested
        if update_activity:
            session.update_activity()
            self._store_session(session)
        
        return session
    
    def _store_session(self, session: Session) -> None:
        """Store session in storage backend"""
        key = f"session:{session.session_id}"
        data = pickle.dumps(session.to_dict())
        ttl = None
        
        if session.expires_at:
            ttl = int(session.expires_at - time.time())
            if ttl <= 0:
                return  # Don't store expired sessions
        
        self.storage.set(key, data, ttl)
        
        # Also store user -> sessions mapping
        self._add_user_session_mapping(session.user_id, session.session_id)
    
    def destroy_session(self, session_id: str) -> bool:
        """Destroy a session"""
        session = self.get_session(session_id, update_activity=False)
        if session:
            self._remove_user_session_mapping(session.user_id, session_id)
        
        self.storage.delete(f"session:{session_id}")
        self._revoked_sessions.discard(session_id)
        return True
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke a session (mark as invalid but keep record)"""
        session = self.get_session(session_id, update_activity=False)
        if not session:
            return False
        
        session.status = SessionStatus.REVOKED
        self._revoked_sessions.add(session_id)
        self._store_session(session)
        return True
    
    def extend_session(self, session_id: str, extra_seconds: int) -> bool:
        """Extend session timeout"""
        session = self.get_session(session_id, update_activity=False)
        if not session:
            return False
        
        if session.expires_at:
            session.expires_at += extra_seconds
        else:
            session.expires_at = time.time() + extra_seconds
        
        session.update_activity()
        self._store_session(session)
        return True
    
    def get_user_sessions(self, user_id: str) -> List[Session]:
        """Get all active sessions for a user"""
        session_ids = self._get_user_session_ids(user_id)
        sessions = []
        
        for session_id in session_ids:
            session = self.get_session(session_id, update_activity=False)
            if session and session.status == SessionStatus.ACTIVE:
                sessions.append(session)
        
        return sessions
    
    def revoke_all_user_sessions(self, user_id: str) -> int:
        """Revoke all sessions for a user"""
        sessions = self.get_user_sessions(user_id)
        count = 0
        
        for session in sessions:
            if self.revoke_session(session.session_id):
                count += 1
        
        return count
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up all expired sessions"""
        session_keys = self.storage.keys("session:*")
        cleaned = 0
        
        for key in session_keys:
            session_id = key.replace("session:", "")
            session = self.get_session(session_id, update_activity=False)
            if not session:  # Will be None if expired
                cleaned += 1
        
        return cleaned
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        session_keys = self.storage.keys("session:*")
        active_sessions = 0
        expired_sessions = 0
        total_users = set()
        
        for key in session_keys:
            session_id = key.replace("session:", "")
            session = self.get_session(session_id, update_activity=False)
            if session:
                active_sessions += 1
                total_users.add(session.user_id)
            else:
                expired_sessions += 1
        
        return {
            'total_sessions': len(session_keys),
            'active_sessions': active_sessions,
            'expired_sessions': expired_sessions,
            'unique_users': len(total_users),
            'revoked_sessions': len(self._revoked_sessions)
        }
    
    def _count_user_sessions(self, user_id: str) -> int:
        """Count active sessions for a user"""
        return len(self.get_user_sessions(user_id))
    
    def _cleanup_oldest_user_session(self, user_id: str) -> None:
        """Remove the oldest session for a user"""
        sessions = self.get_user_sessions(user_id)
        if sessions:
            oldest = min(sessions, key=lambda s: s.created_at)
            self.destroy_session(oldest.session_id)
    
    def _add_user_session_mapping(self, user_id: str, session_id: str) -> None:
        """Add session to user mapping"""
        key = f"user_sessions:{user_id}"
        existing_data = self.storage.get(key)
        
        if existing_data:
            session_ids = pickle.loads(existing_data)
        else:
            session_ids = set()
        
        session_ids.add(session_id)
        self.storage.set(key, pickle.dumps(session_ids))
    
    def _remove_user_session_mapping(self, user_id: str, session_id: str) -> None:
        """Remove session from user mapping"""
        key = f"user_sessions:{user_id}"
        existing_data = self.storage.get(key)
        
        if existing_data:
            session_ids = pickle.loads(existing_data)
            session_ids.discard(session_id)
            if session_ids:
                self.storage.set(key, pickle.dumps(session_ids))
            else:
                self.storage.delete(key)
    
    def _get_user_session_ids(self, user_id: str) -> set:
        """Get all session IDs for a user"""
        key = f"user_sessions:{user_id}"
        data = self.storage.get(key)
        return pickle.loads(data) if data else set()

# Example usage and integration
def example_usage():
    """Example of how to use the session management system"""
    
    # Initialize with in-memory storage
    storage = MemoryStorage()
    session_manager = SessionManager(storage, timeout_seconds=1800)  # 30 minutes
    
    # Create a user
    session_manager.user_manager.create_user("john_doe", "secure_password", 
                                           email="john@example.com", role="user")
    
    # Authenticate and create session
    if session_manager.user_manager.authenticate("john_doe", "secure_password"):
        session = session_manager.create_session(
            user_id="john_doe",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0...",
            custom_data="some value"
        )
        print(f"Session created: {session.session_id}")
    
    # Later, validate session
    if session:
        retrieved_session = session_manager.get_session(session.session_id)
        if retrieved_session:
            print(f"Session valid for user: {retrieved_session.user_id}")
            print(f"Session data: {retrieved_session.data}")
        
        # Get session statistics
        stats = session_manager.get_session_stats()
        print(f"Session stats: {stats}")
        
        # Revoke session
        session_manager.revoke_session(session.session_id)
        
        # Try to get revoked session
        revoked = session_manager.get_session(session.session_id)
        print(f"Revoked session: {revoked}")  # Should be None

# Flask integration example
"""
from flask import Flask, request, session as flask_session, redirect, url_for, jsonify

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Initialize session manager
storage = MemoryStorage()  # or RedisStorage() for production
session_manager = SessionManager(storage, timeout_seconds=3600)

@app.before_request
def check_session():
    # Skip authentication for login endpoints
    if request.endpoint in ['login', 'register']:
        return
    
    session_id = flask_session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    
    user_session = session_manager.get_session(session_id)
    if not user_session:
        flask_session.clear()
        return redirect(url_for('login'))
    
    # Make session available to request context
    request.user_session = user_session

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    if session_manager.user_manager.authenticate(username, password):
        session = session_manager.create_session(
            user_id=username,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        flask_session['session_id'] = session.session_id
        return jsonify({'success': True, 'session_id': session.session_id})
    
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session_id = flask_session.get('session_id')
    if session_id:
        session_manager.destroy_session(session_id)
    flask_session.clear()
    return jsonify({'success': True})

@app.route('/profile')
def profile():
    user_session = request.user_session
    user_info = session_manager.user_manager.get_user(user_session.user_id)
    return jsonify({
        'user': user_info,
        'session_info': {
            'created_at': datetime.datetime.fromtimestamp(user_session.created_at).isoformat(),
            'last_activity': datetime.datetime.fromtimestamp(user_session.last_activity).isoformat()
        }
    })
"""

if __name__ == "__main__":
    example_usage()
