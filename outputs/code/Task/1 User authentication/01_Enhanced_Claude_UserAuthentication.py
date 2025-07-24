"""
Secure User Authentication System
--------------------------------
This module implements a secure user authentication system with the following features:
- Password hashing using Argon2id (memory-hard algorithm)
- Rate limiting to prevent brute force attacks
- Account lockout after multiple failed attempts
- Secure password reset functionality
- Password complexity enforcement
- Protection against timing attacks
- Input validation and sanitization
- Secure session management
"""

import argon2
import secrets
import re
import time
import logging
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, request, session, redirect, url_for, render_template, flash
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from email_validator import validate_email, EmailNotValidError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='auth_system.log'
)
logger = logging.getLogger('auth_system')

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate a secure random key
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Provide CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # 1 hour session timeout

# Enable CSRF protection
csrf = CSRFProtect(app)

# Initialize Argon2 password hasher
ph = argon2.PasswordHasher(
    time_cost=3,  # Iterations
    memory_cost=65536,  # 64 MB
    parallelism=4,  # Number of parallel threads
    hash_len=32,  # Length of the hash in bytes
    salt_len=16,  # Length of the salt in bytes
    encoding='utf-8'  # Encoding of the password
)

# Database initialization
def init_db():
    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        failed_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,
        role TEXT DEFAULT 'user',
        totp_secret TEXT
    )
    ''')
    
    # Login attempts table for rate limiting
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        username TEXT
    )
    ''')
    
    # Password reset tokens
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # User sessions
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_id TEXT UNIQUE NOT NULL,
        ip_address TEXT NOT NULL,
        user_agent TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.commit()
    conn.close()

# Initialize the database on startup
init_db()

# Security utility functions
def get_db_connection():
    """Create a database connection with proper settings"""
    conn = sqlite3.connect('auth.db')
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn

def check_rate_limit(ip_address, username=None):
    """
    Check if the IP address or username has exceeded the rate limit
    Return True if rate limit exceeded, False otherwise
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Delete old entries (older than 10 minutes)
    cursor.execute(
        "DELETE FROM login_attempts WHERE timestamp < datetime('now', '-10 minutes')"
    )
    
    # Check IP address rate limit (15 attempts per 10 minutes)
    cursor.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND timestamp > datetime('now', '-10 minutes')",
        (ip_address,)
    )
    ip_count = cursor.fetchone()[0]
    
    # Check username rate limit if provided (5 attempts per 10 minutes)
    username_count = 0
    if username:
        cursor.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND timestamp > datetime('now', '-10 minutes')",
            (username,)
        )
        username_count = cursor.fetchone()[0]
    
    conn.close()
    
    # Return True if either limit is exceeded
    return (ip_count >= 15) or (username and username_count >= 5)

def record_login_attempt(ip_address, username=None, success=False):
    """Record a login attempt in the database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT INTO login_attempts (ip_address, username) VALUES (?, ?)",
        (ip_address, username)
    )
    
    if not success and username:
        # Increment failed attempts for user
        cursor.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?",
            (username,)
        )
        
        # Check if account should be locked
        cursor.execute(
            "SELECT failed_attempts FROM users WHERE username = ?",
            (username,)
        )
        result = cursor.fetchone()
        if result and result[0] >= 5:
            # Lock account for 15 minutes
            cursor.execute(
                "UPDATE users SET locked_until = datetime('now', '+15 minutes') WHERE username = ?",
                (username,)
            )
            logger.warning(f"Account locked for 15 minutes: {username}")
    
    elif success and username:
        # Reset failed attempts on successful login
        cursor.execute(
            "UPDATE users SET failed_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE username = ?",
            (username,)
        )
    
    conn.commit()
    conn.close()

def is_account_locked(username):
    """Check if the user account is locked"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT locked_until FROM users WHERE username = ?",
        (username,)
    )
    result = cursor.fetchone()
    conn.close()
    
    if not result or not result[0]:
        return False
        
    locked_until = datetime.fromisoformat(result[0].replace('Z', '+00:00'))
    return locked_until > datetime.now()

def verify_password(stored_hash, password):
    """
    Verify a password against a stored hash using constant-time comparison
    to prevent timing attacks
    """
    try:
        ph.verify(stored_hash, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False

def validate_password_strength(password):
    """
    Validate password strength with the following rules:
    - At least 12 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    - Contains at least one special character
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
        
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
        
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
        
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
        
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?]', password):
        return False, "Password must contain at least one special character"
        
    # Check for common password patterns
    common_patterns = [
        'password', '123456', 'qwerty', 'admin', 'welcome',
        'letmein', 'monkey', 'abc123', 'dragon', 'baseball'
    ]
    if any(pattern in password.lower() for pattern in common_patterns):
        return False, "Password contains common patterns"
        
    return True, "Password meets strength requirements"

def generate_session_id():
    """Generate a secure random session ID"""
    return secrets.token_urlsafe(32)

def create_session(user_id, ip_address, user_agent):
    """Create a new session for the user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    session_id = generate_session_id()
    expires_at = datetime.now() + timedelta(hours=1)
    
    cursor.execute(
        """
        INSERT INTO sessions 
        (user_id, session_id, ip_address, user_agent, expires_at) 
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, session_id, ip_address, user_agent, expires_at)
    )
    
    conn.commit()
    conn.close()
    
    return session_id

def validate_session(session_id, ip_address, user_agent):
    """Validate a session and return user_id if valid"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        """
        SELECT user_id FROM sessions 
        WHERE session_id = ? AND is_active = 1 AND expires_at > CURRENT_TIMESTAMP
        """,
        (session_id,)
    )
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return None
        
    # Additional security check for IP and user agent (optional - can be removed if causing issues)
    # This helps prevent session hijacking but may cause issues if user's IP changes
    # cursor.execute(
    #     "SELECT user_id FROM sessions WHERE session_id = ? AND ip_address = ? AND user_agent = ?",
    #     (session_id, ip_address, user_agent)
    # )
    # result = cursor.fetchone()
    # conn.close()
    
    return result[0] if result else None

def generate_password_reset_token(user_id):
    """Generate a secure token for password reset"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Generate a secure token
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=1)
    
    # Invalidate existing tokens for this user
    cursor.execute(
        "UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0",
        (user_id,)
    )
    
    # Store new token
    cursor.execute(
        """
        INSERT INTO password_reset_tokens 
        (user_id, token, expires_at) 
        VALUES (?, ?, ?)
        """,
        (user_id, token, expires_at)
    )
    
    conn.commit()
    conn.close()
    
    return token

def validate_reset_token(token):
    """Validate a password reset token"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        """
        SELECT user_id FROM password_reset_tokens 
        WHERE token = ? AND used = 0 AND expires_at > CURRENT_TIMESTAMP
        """,
        (token,)
    )
    result = cursor.fetchone()
    
    conn.close()
    
    return result[0] if result else None

def sanitize_input(input_str):
    """Sanitize user input to prevent injection attacks"""
    if input_str is None:
        return None
    
    # Remove any control characters
    sanitized = re.sub(r'[\x00-\x1F\x7F]', '', input_str)
    
    # Convert HTML entities
    sanitized = sanitized.replace('&', '&amp;')
    sanitized = sanitized.replace('<', '&lt;')
    sanitized = sanitized.replace('>', '&gt;')
    sanitized = sanitized.replace('"', '&quot;')
    sanitized = sanitized.replace("'", '&#x27;')
    
    return sanitized

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Route handlers
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get and sanitize form data
        username = sanitize_input(request.form.get('username', '').strip())
        email = sanitize_input(request.form.get('email', '').strip())
        password = request.form.get('password', '')  # Don't sanitize passwords
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate input
        errors = []
        
        # Username validation
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters long")
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            errors.append("Username can only contain letters, numbers, underscores and hyphens")
        
        # Email validation
        try:
            validate_email(email)
        except EmailNotValidError as e:
            errors.append(f"Invalid email: {str(e)}")
        
        # Password validation
        if password != confirm_password:
            errors.append("Passwords do not match")
        
        password_valid, password_error = validate_password_strength(password)
        if not password_valid:
            errors.append(password_error)
        
        # If validation passes, check if username or email already exists
        if not errors:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                errors.append("Username already exists")
            
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                errors.append("Email already registered")
            
            conn.close()
        
        # If no errors, create the new user
        if not errors:
            # Hash the password with Argon2id
            password_hash = ph.hash(password)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, password_hash)
                )
                conn.commit()
                flash("Registration successful! Please log in.", "success")
                logger.info(f"New user registered: {username}")
                return redirect(url_for('login'))
            except Exception as e:
                conn.rollback()
                logger.error(f"Error creating user: {e}")
                errors.append("An error occurred. Please try again later.")
            finally:
                conn.close()
        
        # If there were errors, display them
        for error in errors:
            flash(error, "error")
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        username = sanitize_input(request.form.get('username', '').strip())
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me') == 'on'
        
        # Get client information for security checks
        ip_address = request.remote_addr
        user_agent = request.user_agent.string
        
        # Check rate limiting before attempting login
        if check_rate_limit(ip_address, username):
            flash("Too many login attempts. Please try again later.", "error")
            logger.warning(f"Rate limit exceeded for IP: {ip_address}, Username: {username}")
            return render_template('login.html')
        
        # Check if account is locked
        if username and is_account_locked(username):
            flash("This account is temporarily locked due to multiple failed login attempts.", "error")
            return render_template('login.html')
        
        # Record this login attempt
        record_login_attempt(ip_address, username)
        
        # Attempt to retrieve user
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, password_hash FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        
        if not user or not verify_password(user['password_hash'], password):
            # Introduce a small delay to make timing attacks harder
            time.sleep(secrets.randbelow(100) / 1000)  # 0-100ms delay
            flash("Invalid username or password", "error")
            logger.warning(f"Failed login attempt for username: {username}")
            return render_template('login.html')
        
        # At this point, login is successful
        user_id = user['id']
        
        # Record successful login attempt and reset failed attempts counter
        record_login_attempt(ip_address, username, success=True)
        
        # Create a new session
        session_id = create_session(user_id, ip_address, user_agent)
        
        # Store user information in the session
        session.clear()
        session['user_id'] = user_id
        session['session_id'] = session_id
        
        # Set session to permanent if remember_me is checked
        if remember_me:
            session.permanent = True
            app.permanent_session_lifetime = timedelta(days=7)  # 7 days
        
        logger.info(f"User logged in: {username}")
        flash("Login successful!", "success")
        return redirect(url_for('dashboard'))
        
        conn.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    # Invalidate the session in the database
    if 'session_id' in session:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE sessions SET is_active = 0 WHERE session_id = ?",
            (session['session_id'],)
        )
        conn.commit()
        conn.close()
    
    # Clear the session data
    session.clear()
    
    flash("You have been logged out successfully", "success")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user information
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT username, email, created_at, last_login FROM users WHERE id = ?",
        (session['user_id'],)
    )
    user = cursor.fetchone()
    
    # Get active sessions
    cursor.execute(
        """
        SELECT id, ip_address, user_agent, created_at 
        FROM sessions 
        WHERE user_id = ? AND is_active = 1 AND expires_at > CURRENT_TIMESTAMP
        """,
        (session['user_id'],)
    )
    active_sessions = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', user=user, active_sessions=active_sessions)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = sanitize_input(request.form.get('email', '').strip())
        
        # Validate email format
        try:
            validate_email(email)
        except EmailNotValidError:
            flash("Please enter a valid email address", "error")
            return render_template('forgot_password.html')
        
        # Check if email exists in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        
        if user:
            # Generate and store password reset token
            token = generate_password_reset_token(user['id'])
            
            # Send email with reset link - in a real application, you would use an email service here
            reset_link = f"{request.host_url}reset-password/{token}"
            print(f"Password reset link for {email}: {reset_link}")
            logger.info(f"Password reset token generated for user ID: {user['id']}")
            
            # In a real application, you would not want to log the actual token:
            # logger.info(f"Password reset requested for user ID: {user['id']}")
            
            # For demonstration purposes only:
            flash(f"A password reset link has been sent to {email}. For demo purposes, link: {reset_link}", "success")
        else:
            # Don't reveal if the email exists or not for security
            flash("If that email is registered, you will receive a password reset link", "info")
        
        conn.close()
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Validate token first
    user_id = validate_reset_token(token)
    
    if not user_id:
        flash("Invalid or expired password reset link", "error")
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate passwords
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template('reset_password.html', token=token)
        
        password_valid, password_error = validate_password_strength(password)
        if not password_valid:
            flash(password_error, "error")
            return render_template('reset_password.html', token=token)
        
        # Update the password
        try:
            # Hash the new password
            password_hash = ph.hash(password)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Update the password
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id)
            )
            
            # Mark the token as used
            cursor.execute(
                "UPDATE password_reset_tokens SET used = 1 WHERE token = ?",
                (token,)
            )
            
            # Invalidate all active sessions for security
            cursor.execute(
                "UPDATE sessions SET is_active = 0 WHERE user_id = ?",
                (user_id,)
            )
            
            conn.commit()
            conn.close()
            
            flash("Your password has been reset successfully. Please log in with your new password.", "success")
            logger.info(f"Password reset successful for user ID: {user_id}")
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Error resetting password: {e}")
            flash("An error occurred. Please try again later.", "error")
            return render_template('reset_password.html', token=token)
    
    return render_template('reset_password.html', token=token)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate form data
        if not current_password or not new_password or not confirm_password:
            flash("All fields are required", "error")
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash("New passwords do not match", "error")
            return render_template('change_password.html')
        
        password_valid, password_error = validate_password_strength(new_password)
        if not password_valid:
            flash(password_error, "error")
            return render_template('change_password.html')
        
        # Verify current password
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT password_hash FROM users WHERE id = ?",
            (session['user_id'],)
        )
        user = cursor.fetchone()
        
        if not user or not verify_password(user['password_hash'], current_password):
            flash("Current password is incorrect", "error")
            conn.close()
            return render_template('change_password.html')
        
        # Update the password
        try:
            # Hash the new password
            password_hash = ph.hash(new_password)
            
            # Update the password
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, session['user_id'])
            )
            
            # Keep the current session active but invalidate all other sessions
            cursor.execute(
                """
                UPDATE sessions SET is_active = 0 
                WHERE user_id = ? AND session_id != ?
                """,
                (session['user_id'], session.get('session_id', ''))
            )
            
            conn.commit()
            flash("Your password has been changed successfully", "success")
            logger.info(f"Password changed for user ID: {session['user_id']}")
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error changing password: {e}")
            flash("An error occurred. Please try again later.", "error")
            
        finally:
            conn.close()
    
    return render_template('change_password.html')

@app.route('/sessions')
@login_required
def manage_sessions():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        """
        SELECT id, ip_address, user_agent, created_at 
        FROM sessions 
        WHERE user_id = ? AND is_active = 1 AND expires_at > CURRENT_TIMESTAMP
        """,
        (session['user_id'],)
    )
    active_sessions = cursor.fetchall()
    
    conn.close()
    
    return render_template('sessions.html', active_sessions=active_sessions)

@app.route('/sessions/revoke/<int:session_id>', methods=['POST'])
@login_required
def revoke_session(session_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Ensure the session belongs to the current user
    cursor.execute(
        """
        SELECT id FROM sessions 
        WHERE id = ? AND user_id = ?
        """,
        (session_id, session['user_id'])
    )
    session_record = cursor.fetchone()
    
    if session_record:
        cursor.execute(
            "UPDATE sessions SET is_active = 0 WHERE id = ?",
            (session_id,)
        )
        conn.commit()
        flash("Session revoked successfully", "success")
    else:
        flash("Invalid session", "error")
    
    conn.close()
    
    # If the current session was revoked, log out
    if str(session_id) == session.get('session_id'):
        return redirect(url_for('logout'))
    
    return redirect(url_for('manage_sessions'))

@app.route('/sessions/revoke-all', methods=['POST'])
@login_required
def revoke_all_sessions():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Revoke all sessions except the current one
    cursor.execute(
        """
        UPDATE sessions SET is_active = 0 
        WHERE user_id = ? AND session_id != ?
        """,
        (session['user_id'], session.get('session_id', ''))
    )
    conn.commit()
    conn.close()
    
    flash("All other sessions have been revoked", "success")
    return redirect(url_for('manage_sessions'))

if __name__ == '__main__':
    # Use a production WSGI server like Gunicorn in production
    app.run(host='0.0.0.0', port=5000, debug=False, ssl_context='adhoc')
