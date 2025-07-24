import secrets
import hashlib
import time
import json
import redis
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict
from flask import Flask, request, jsonify, session as flask_session
from cryptography.fernet import Fernet
import pytz
from functools import wraps
import ipaddress
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('session_security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('session_manager')

@dataclass
class SessionData:
    """Data structure for session information."""
    session_id: str
    user_id: str
    username: str
    created_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    roles: list
    is_active: bool = True
    login_attempts: int = 0
    csrf_token: str = None

class SecureSessionManager:
    """Comprehensive secure session management system."""
    
    def __init__(self, redis_client=None, secret_key=None):
        """Initialize the session manager with security configurations."""
        self.redis_client = redis_client or redis.Redis(
            host='localhost', 
            port=6379, 
            db=0,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5
        )
        
        # Generate or use provided secret key for encryption
        self.secret_key = secret_key or Fernet.generate_key()
        self.cipher = Fernet(self.secret_key)
        
        # Session configuration
        self.SESSION_TIMEOUT = 30 * 60  # 30 minutes in seconds
        self.MAX_SESSIONS_PER_USER = 3  # Maximum concurrent sessions per user
        self.SESSION_RENEWAL_THRESHOLD = 5 * 60  # Renew session if 5 minutes left
        self.MAX_LOGIN_ATTEMPTS = 5
        self.LOCKOUT_DURATION = 15 * 60  # 15 minutes lockout
        
        # Security settings
        self.SECURE_HEADERS = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        }
    
    def generate_session_id(self) -> str:
        """Generate a cryptographically secure session ID."""
        # Use 32 bytes of random data for high entropy
        random_bytes = secrets.token_bytes(32)
        timestamp = str(time.time()).encode()
        
        # Create a hash that includes timestamp to prevent collisions
        hash_input = random_bytes + timestamp
        session_id = hashlib.sha256(hash_input).hexdigest()
        
        return session_id
    
    def generate_csrf_token(self) -> str:
        """Generate a CSRF token for the session."""
        return secrets.token_urlsafe(32)
    
    def encrypt_session_data(self, data: dict) -> str:
        """Encrypt session data before storing."""
        json_data = json.dumps(data, default=str)
        encrypted_data = self.cipher.encrypt(json_data.encode())
        return encrypted_data.decode()
    
    def decrypt_session_data(self, encrypted_data: str) -> dict:
        """Decrypt session data after retrieving."""
        try:
            decrypted_data = self.cipher.decrypt(encrypted_data.encode())
            return json.loads(decrypted_data.decode())
        except Exception as e:
            logger.error(f"Failed to decrypt session data: {e}")
            return {}
    
    def validate_ip_address(self, ip_address: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def validate_user_agent(self, user_agent: str) -> bool:
        """Basic validation of user agent string."""
        if not user_agent or len(user_agent) > 500:
            return False
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'<script',
            r'javascript:',
            r'on\w+\s*=',
            r'expression\s*\(',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return False
        
        return True
    
    def create_session(self, user_id: str, username: str, roles: list, 
                      ip_address: str, user_agent: str) -> Optional[str]:
        """Create a new secure session."""
        try:
            # Validate inputs
            if not self.validate_ip_address(ip_address):
                logger.warning(f"Invalid IP address: {ip_address}")
                return None
            
            if not self.validate_user_agent(user_agent):
                logger.warning(f"Invalid user agent: {user_agent}")
                return None
            
            # Check if user has too many active sessions
            user_sessions = self.get_user_sessions(user_id)
            if len(user_sessions) >= self.MAX_SESSIONS_PER_USER:
                # Remove oldest session
                oldest_session = min(user_sessions, key=lambda x: x['last_activity'])
                self.destroy_session(oldest_session['session_id'])
                logger.info(f"Removed oldest session for user {user_id}")
            
            # Generate session ID and CSRF token
            session_id = self.generate_session_id()
            csrf_token = self.generate_csrf_token()
            
            # Create session data
            current_time = datetime.now(pytz.UTC)
            session_data = SessionData(
                session_id=session_id,
                user_id=user_id,
                username=username,
                created_at=current_time,
                last_activity=current_time,
                ip_address=ip_address,
                user_agent=user_agent,
                roles=roles,
                csrf_token=csrf_token
            )
            
            # Encrypt and store session data
            encrypted_data = self.encrypt_session_data(asdict(session_data))
            session_key = f"session:{session_id}"
            user_session_key = f"user_sessions:{user_id}"
            
            # Store in Redis with expiration
            pipe = self.redis_client.pipeline()
            pipe.setex(session_key, self.SESSION_TIMEOUT, encrypted_data)
            pipe.sadd(user_session_key, session_id)
            pipe.expire(user_session_key, self.SESSION_TIMEOUT)
            pipe.execute()
            
            logger.info(f"Created session {session_id} for user {username}")
            return session_id
            
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            return None
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Retrieve and validate a session."""
        try:
            session_key = f"session:{session_id}"
            encrypted_data = self.redis_client.get(session_key)
            
            if not encrypted_data:
                return None
            
            session_data = self.decrypt_session_data(encrypted_data)
            if not session_data:
                return None
            
            # Convert datetime strings back to datetime objects
            session_data['created_at'] = datetime.fromisoformat(session_data['created_at'])
            session_data['last_activity'] = datetime.fromisoformat(session_data['last_activity'])
            
            return session_data
            
        except Exception as e:
            logger.error(f"Failed to retrieve session {session_id}: {e}")
            return None
    
    def validate_session(self, session_id: str, ip_address: str, 
                        user_agent: str) -> tuple[bool, Optional[Dict]]:
        """Validate a session and check for security issues."""
        session_data = self.get_session(session_id)
        
        if not session_data:
            return False, None
        
        current_time = datetime.now(pytz.UTC)
        
        # Check if session has expired
        time_since_activity = (current_time - session_data['last_activity']).total_seconds()
        if time_since_activity > self.SESSION_TIMEOUT:
            logger.info(f"Session {session_id} expired")
            self.destroy_session(session_id)
            return False, None
        
        # Check for IP address change (potential session hijacking)
        if session_data['ip_address'] != ip_address:
            logger.warning(f"IP address mismatch for session {session_id}: "
                         f"expected {session_data['ip_address']}, got {ip_address}")
            self.destroy_session(session_id)
            return False, None
        
        # Check for User-Agent change (potential session hijacking)
        if session_data['user_agent'] != user_agent:
            logger.warning(f"User-Agent mismatch for session {session_id}")
            self.destroy_session(session_id)
            return False, None
        
        # Session is valid - update last activity
        session_data['last_activity'] = current_time
        self.update_session_activity(session_id, session_data)
        
        return True, session_data
    
    def update_session_activity(self, session_id: str, session_data: Dict):
        """Update the last activity time for a session."""
        try:
            session_key = f"session:{session_id}"
            encrypted_data = self.encrypt_session_data(session_data)
            
            # Update session data and reset expiration
            pipe = self.redis_client.pipeline()
            pipe.setex(session_key, self.SESSION_TIMEOUT, encrypted_data)
            pipe.execute()
            
        except Exception as e:
            logger.error(f"Failed to update session activity: {e}")
    
    def destroy_session(self, session_id: str) -> bool:
        """Destroy a session securely."""
        try:
            session_data = self.get_session(session_id)
            if session_data:
                user_id = session_data['user_id']
                
                # Remove from Redis
                session_key = f"session:{session_id}"
                user_session_key = f"user_sessions:{user_id}"
                
                pipe = self.redis_client.pipeline()
                pipe.delete(session_key)
                pipe.srem(user_session_key, session_id)
                pipe.execute()
                
                logger.info(f"Destroyed session {session_id} for user {user_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to destroy session {session_id}: {e}")
            return False
    
    def get_user_sessions(self, user_id: str) -> list:
        """Get all active sessions for a user."""
        try:
            user_session_key = f"user_sessions:{user_id}"
            session_ids = self.redis_client.smembers(user_session_key)
            
            sessions = []
            for session_id in session_ids:
                session_data = self.get_session(session_id)
                if session_data:
                    sessions.append(session_data)
                else:
                    # Clean up invalid session ID
                    self.redis_client.srem(user_session_key, session_id)
            
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to get user sessions: {e}")
            return []
    
    def destroy_all_user_sessions(self, user_id: str) -> bool:
        """Destroy all sessions for a user (e.g., on password change)."""
        try:
            sessions = self.get_user_sessions(user_id)
            
            for session in sessions:
                self.destroy_session(session['session_id'])
            
            # Clean up user session set
            user_session_key = f"user_sessions:{user_id}"
            self.redis_client.delete(user_session_key)
            
            logger.info(f"Destroyed all sessions for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to destroy all user sessions: {e}")
            return False
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions (run periodically)."""
        try:
            # This would typically be run as a background task
            pattern = "session:*"
            for key in self.redis_client.scan_iter(match=pattern):
                session_id = key.split(':')[1]
                session_data = self.get_session(session_id)
                
                if not session_data:
                    continue
                
                current_time = datetime.now(pytz.UTC)
                time_since_activity = (current_time - session_data['last_activity']).total_seconds()
                
                if time_since_activity > self.SESSION_TIMEOUT:
                    self.destroy_session(session_id)
                    logger.info(f"Cleaned up expired session {session_id}")
                    
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")

# Flask application with session management
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Initialize session manager
session_manager = SecureSessionManager()

def require_session(f):
    """Decorator to require valid session for route access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = request.headers.get('X-Session-ID') or request.cookies.get('session_id')
        
        if not session_id:
            return jsonify({'error': 'No session ID provided'}), 401
        
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        is_valid, session_data = session_manager.validate_session(
            session_id, ip_address, user_agent
        )
        
        if not is_valid:
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        # Add session data to Flask's g object for use in routes
        from flask import g
        g.session_data = session_data
        
        return f(*args, **kwargs)
    
    return decorated_function

@app.route('/api/login', methods=['POST'])
def login():
    """Login endpoint that creates a new session."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Authenticate user (implement your authentication logic)
    user_id, roles = authenticate_user(username, password)
    
    if not user_id:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Create new session
    session_id = session_manager.create_session(
        user_id=user_id,
        username=username,
        roles=roles,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')
    )
    
    if not session_id:
        return jsonify({'error': 'Failed to create session'}), 500
    
    response = jsonify({
        'message': 'Login successful',
        'session_id': session_id
    })
    
    # Set secure cookie
    response.set_cookie(
        'session_id',
        session_id,
        max_age=session_manager.SESSION_TIMEOUT,
        secure=True,
        httponly=True,
        samesite='Lax'
    )
    
    # Add security headers
    for header, value in session_manager.SECURE_HEADERS.items():
        response.headers[header] = value
    
    return response

@app.route('/api/logout', methods=['POST'])
@require_session
def logout():
    """Logout endpoint that destroys the current session."""
    from flask import g
    session_id = g.session_data['session_id']
    
    session_manager.destroy_session(session_id)
    
    response = jsonify({'message': 'Logout successful'})
    response.set_cookie('session_id', '', expires=0)
    
    return response

@app.route('/api/profile')
@require_session
def get_profile():
    """Protected endpoint that requires valid session."""
    from flask import g
    session_data = g.session_data
    
    return jsonify({
        'user_id': session_data['user_id'],
        'username': session_data['username'],
        'roles': session_data['roles'],
        'session_created': session_data['created_at'].isoformat(),
        'last_activity': session_data['last_activity'].isoformat()
    })

def authenticate_user(username: str, password: str) -> tuple[Optional[str], list]:
    """
    Authenticate user against database.
    Returns user_id and roles if successful, None and empty list if failed.
    """
    # Implement your authentication logic here
    # This is just a placeholder
    if username == "admin" and password == "secure_password":
        return "user_123", ["admin", "user"]
    return None, []

if __name__ == '__main__':
    # In production, use proper WSGI server with HTTPS
    app.run(debug=False, ssl_context='adhoc')
