import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, session, request, redirect, url_for, g, abort
from flask_session import Session  # Server-side sessions
import redis
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.update(
    # Security configuration
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    SESSION_COOKIE_NAME='__Secure-sessionid',  # Secure cookie name
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),  # Absolute timeout
    
    # Session storage configuration
    SESSION_TYPE='redis',
    SESSION_REDIS=redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379')),
    SESSION_USE_SIGNER=True,  # Sign session cookies
    SESSION_PERMANENT=True,
    SESSION_KEY_PREFIX='secure_session:'
)

# Initialize server-side session extension
Session(app)

# Timeout configurations (in seconds)
ABSOLUTE_TIMEOUT = 8 * 60 * 60  # 8 hours
INACTIVITY_TIMEOUT = 30 * 60    # 30 minutes

@app.before_request
def enforce_session_security():
    """Enforce session security policies before processing requests"""
    # Initialize session timestamps
    session.setdefault('created_at', datetime.utcnow().isoformat())
    session.setdefault('last_activity', datetime.utcnow().isoformat())
    
    # Convert stored timestamps to datetime objects
    created_at = datetime.fromisoformat(session['created_at'])
    last_activity = datetime.fromisoformat(session['last_activity'])
    current_time = datetime.utcnow()
    
    # Check absolute timeout
    if (current_time - created_at).total_seconds() > ABSOLUTE_TIMEOUT:
        session.clear()
        return redirect(url_for('login'))
    
    # Check inactivity timeout
    if (current_time - last_activity).total_seconds() > INACTIVITY_TIMEOUT:
        session.clear()
        return redirect(url_for('login'))
    
    # Update last activity on valid requests
    if request.method != 'GET' or not request.path.startswith('/static/'):
        session['last_activity'] = current_time.isoformat()
    
    # Implement strict session binding
    session_token = session.get('session_token')
    current_token = request.headers.get('User-Agent', '') + request.remote_addr
    
    if not session_token:
        # First valid request after login
        session['session_token'] = generate_password_hash(current_token)
    elif not check_password_hash(session_token, current_token):
        # Session binding violation
        app.logger.warning(f'Session binding violation: {request.remote_addr}')
        session.clear()
        abort(403, "Session invalidated due to security policy")

@app.route('/login', methods=['POST'])
def login():
    """Authenticate user and initialize session"""
    # Validate credentials
    username = request.form.get('username')
    password = request.form.get('password')
    user = authenticate_user(username, password)
    
    if not user:
        return 'Invalid credentials', 401
    
    # Regenerate session to prevent fixation
    session.regenerate()
    
    # Initialize secure session
    session.permanent = True
    session['user_id'] = user['id']
    session['user_role'] = user['role']
    session['created_at'] = datetime.utcnow().isoformat()
    session['last_activity'] = datetime.utcnow().isoformat()
    
    # Set initial session binding token
    g.session_initialized = True
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    """Terminate session securely"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/sensitive-action')
def sensitive_action():
    """Example sensitive operation requiring re-authentication"""
    if not session.get('reauthenticated'):
        return redirect(url_for('reauthenticate'))
    
    # Perform sensitive action
    return "Sensitive operation completed"

@app.route('/reauthenticate', methods=['GET', 'POST'])
def reauthenticate():
    """Re-authentication for sensitive operations"""
    if request.method == 'POST':
        # Verify credentials again
        if validate_credentials(session['user_id'], request.form.get('password')):
            session['reauthenticated'] = True
            return redirect(url_for('sensitive_action'))
    
    return '''
        <form method="post">
            Password: <input type="password" name="password">
            <input type="submit" value="Verify">
        </form>
    '''

def authenticate_user(username, password):
    """Authenticate user credentials (implement properly in production)"""
    # In production: retrieve hashed password from database
    # Use constant-time comparison
    valid_user = {
        'id': 1,
        'username': 'admin',
        'role': 'admin',
        'password_hash': generate_password_hash('secure_password')
    }
    
    if username == valid_user['username']:
        if check_password_hash(valid_user['password_hash'], password):
            return valid_user
    return None

def validate_credentials(user_id, password):
    """Validate credentials for re-authentication"""
    # In production: fetch user from database
    valid_user = {
        'id': 1,
        'password_hash': generate_password_hash('secure_password')
    }
    
    if user_id == valid_user['id']:
        return check_password_hash(valid_user['password_hash'], password)
    return False

if __name__ == '__main__':
    app.run(ssl_context='adhoc')