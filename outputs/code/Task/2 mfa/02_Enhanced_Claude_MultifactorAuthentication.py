import secrets
import hmac
import hashlib
import time
import base64
import qrcode
from io import BytesIO
import pyotp
from flask import Flask, session, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from argon2 import PasswordHasher
import logging
from logging.handlers import RotatingFileHandler
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(
    handlers=[RotatingFileHandler('mfa_app.log', maxBytes=10000000, backupCount=5)],
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('mfa_app')

app = Flask(__name__)
# Use a properly generated secret key in production
app.secret_key = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True  # Use only with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
ph = PasswordHasher()

# Rate limiting data structure
@dataclass
class RateLimitEntry:
    attempts: int = 0
    reset_time: datetime = None

# In-memory rate limiting store (use Redis in production)
rate_limit_store = {}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    backup_codes = db.Column(db.String(500), nullable=True)  # JSON string of hashed backup codes
    mfa_enabled = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime, nullable=True)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

def rate_limit_check(ip_address, max_attempts=5, window_seconds=300):
    """Check if an IP has exceeded rate limits"""
    now = datetime.now()
    
    if ip_address not in rate_limit_store:
        rate_limit_store[ip_address] = RateLimitEntry(1, now + timedelta(seconds=window_seconds))
        return True
    
    entry = rate_limit_store[ip_address]
    
    # Reset if window expired
    if now > entry.reset_time:
        entry.attempts = 1
        entry.reset_time = now + timedelta(seconds=window_seconds)
        return True
    
    # Check if over limit
    if entry.attempts >= max_attempts:
        return False
    
    # Increment attempts
    entry.attempts += 1
    return True

def generate_backup_codes(count=10):
    """Generate secure backup codes and their hashes"""
    codes = []
    hashed_codes = []
    
    for _ in range(count):
        # Generate a code with format XXXX-XXXX-XXXX (12 alphanumeric chars + 2 hyphens)
        code = f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
        codes.append(code)
        
        # Hash each code for storage
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        hashed_codes.append(code_hash)
    
    return codes, hashed_codes

def is_valid_username(username):
    """Validate username format"""
    pattern = r'^[a-zA-Z0-9_-]{3,32}$'
    return bool(re.match(pattern, username))

def is_strong_password(password):
    """Check if password meets strength requirements"""
    # At least 12 chars, with uppercase, lowercase, numbers and special chars
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[^A-Za-z0-9]', password):
        return False
    return True

@app.before_request
def before_request():
    """Security headers and session management"""
    # Auto-logout after session timeout
    if 'user_id' in session and 'last_activity' in session:
        idle_time = datetime.now() - datetime.fromisoformat(session['last_activity'])
        if idle_time > timedelta(minutes=15):
            session.clear()
            return redirect(url_for('login', message='Session expired'))
    
    if 'user_id' in session:
        session['last_activity'] = datetime.now().isoformat()

@app.after_request
def add_security_headers(response):
    """Add security headers to responses"""
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; frame-ancestors 'none'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), interest-cohort=()'
    return response

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(id=session['user_id']).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=user.username, mfa_enabled=user.mfa_enabled)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Client IP for rate limiting
        client_ip = request.remote_addr
        
        # Apply rate limiting
        if not rate_limit_check(client_ip, max_attempts=5, window_seconds=300):
            logger.warning(f"Rate limit exceeded for registration attempt from {client_ip}")
            return render_template('register.html', error="Too many registration attempts. Please try again later.")
        
        # Validate input
        if not username or not password:
            return render_template('register.html', error="Username and password are required")
        
        if not is_valid_username(username):
            return render_template('register.html', error="Invalid username format")
            
        if not is_strong_password(password):
            return render_template('register.html', error="Password must be at least 12 characters with uppercase, lowercase, numbers, and special characters")
        
        # Check if user exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error="Username already exists")
        
        try:
            # Hash password with Argon2id (memory-hard algorithm)
            hashed_password = ph.hash(password)
            
            # Create new user
            new_user = User(
                username=username,
                password=hashed_password,
                mfa_enabled=False
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            logger.info(f"New user registered: {username}")
            return redirect(url_for('login', message="Registration successful! Please log in."))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error during registration: {str(e)}")
            return render_template('register.html', error="Registration failed. Please try again.")
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Client IP for rate limiting
        client_ip = request.remote_addr
        
        # Apply rate limiting
        if not rate_limit_check(client_ip, max_attempts=5, window_seconds=300):
            logger.warning(f"Rate limit exceeded for login attempt from {client_ip}")
            return render_template('login.html', error="Too many login attempts. Please try again later.")
        
        # Basic validation
        if not username or not password:
            return render_template('login.html', error="Username and password are required")
        
        # Find user
        user = User.query.filter_by(username=username).first()
        if not user:
            # Use constant time comparison to prevent timing attacks
            # Even though user doesn't exist, perform a dummy check
            ph.verify("dummy_hash", password)  # Will fail but take similar time
            logger.warning(f"Failed login attempt for non-existent user: {username}")
            return render_template('login.html', error="Invalid username or password")
        
        # Check if account is locked
        if user.locked_until and datetime.now() < user.locked_until:
            logger.warning(f"Login attempt on locked account: {username}")
            return render_template('login.html', error="Account is temporarily locked. Try again later.")
        
        try:
            # Verify password using Argon2
            ph.verify(user.password, password)
            
            # Reset failed attempts on successful password verification
            user.failed_attempts = 0
            
            # If MFA is enabled, redirect to MFA verification
            if user.mfa_enabled:
                # Store partial auth state securely
                session['partial_auth'] = True
                session['partial_auth_user_id'] = user.id
                session['partial_auth_time'] = datetime.now().isoformat()
                
                # Redirect to MFA verification
                return redirect(url_for('verify_mfa'))
            
            # If MFA is not enabled, complete login
            session.clear()
            session.permanent = True
            session['user_id'] = user.id
            session['last_activity'] = datetime.now().isoformat()
            
            # Update last login timestamp
            user.last_login = datetime.now()
            db.session.commit()
            
            logger.info(f"User logged in: {username}")
            return redirect(url_for('index'))
            
        except Exception as e:
            # Increment failed attempts
            user.failed_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.failed_attempts >= 5:
                user.locked_until = datetime.now() + timedelta(minutes=15)
                logger.warning(f"Account locked due to failed attempts: {username}")
            
            db.session.commit()
            
            logger.warning(f"Failed login attempt for user: {username}")
            return render_template('login.html', error="Invalid username or password")
    
    # GET request
    message = request.args.get('message')
    return render_template('login.html', message=message)

@app.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    # Ensure user has partial authentication
    if 'partial_auth' not in session or not session['partial_auth']:
        return redirect(url_for('login'))
    
    # Check for partial auth timeout (5 minute limit)
    auth_time = datetime.fromisoformat(session['partial_auth_time'])
    if datetime.now() - auth_time > timedelta(minutes=5):
        session.clear()
        return redirect(url_for('login', message="MFA verification timeout. Please log in again."))
    
    user_id = session.get('partial_auth_user_id')
    user = User.query.get(user_id)
    
    if not user or not user.mfa_enabled:
        session.clear()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        totp_code = request.form.get('totp_code', '').strip()
        backup_code = request.form.get('backup_code', '').strip()
        
        # Client IP for rate limiting
        client_ip = request.remote_addr
        
        # Apply strict rate limiting for MFA attempts
        if not rate_limit_check(f"{client_ip}_mfa", max_attempts=3, window_seconds=300):
            logger.warning(f"MFA rate limit exceeded for user ID: {user_id}")
            return render_template('verify_mfa.html', error="Too many verification attempts. Please try again later.")
        
        # Verify TOTP code
        if totp_code:
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(totp_code):
                # Complete login
                session.clear()
                session.permanent = True
                session['user_id'] = user.id
                session['last_activity'] = datetime.now().isoformat()
                
                # Update last login timestamp
                user.last_login = datetime.now()
                db.session.commit()
                
                logger.info(f"User completed MFA login with TOTP: ID {user.id}")
                return redirect(url_for('index'))
            else:
                logger.warning(f"Failed TOTP verification attempt for user ID: {user.id}")
                return render_template('verify_mfa.html', error="Invalid verification code")
        
        # Verify backup code
        elif backup_code:
            if not user.backup_codes:
                return render_template('verify_mfa.html', error="No backup codes available")
            
            import json
            hashed_backup_codes = json.loads(user.backup_codes)
            
            # Hash the provided backup code
            backup_code_hash = hashlib.sha256(backup_code.encode()).hexdigest()
            
            if backup_code_hash in hashed_backup_codes:
                # Remove the used backup code
                hashed_backup_codes.remove(backup_code_hash)
                user.backup_codes = json.dumps(hashed_backup_codes)
                
                # Complete login
                session.clear()
                session.permanent = True
                session['user_id'] = user.id
                session['last_activity'] = datetime.now().isoformat()
                
                # Update last login timestamp
                user.last_login = datetime.now()
                db.session.commit()
                
                logger.info(f"User completed MFA login with backup code: ID {user.id}")
                return redirect(url_for('index'))
            else:
                logger.warning(f"Failed backup code verification attempt for user ID: {user.id}")
                return render_template('verify_mfa.html', error="Invalid backup code")
        
        else:
            return render_template('verify_mfa.html', error="Please provide a verification code")
    
    return render_template('verify_mfa.html')

@app.route('/setup-mfa', methods=['GET', 'POST'])
def setup_mfa():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(id=session['user_id']).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    if user.mfa_enabled:
        return redirect(url_for('index', message="MFA is already enabled"))
    
    if request.method == 'POST':
        verification_code = request.form.get('verification_code', '').strip()
        
        # Verify the setup
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(verification_code):
            # Generate backup codes
            backup_codes, hashed_backup_codes = generate_backup_codes()
            
            # Enable MFA
            user.mfa_enabled = True
            user.backup_codes = json.dumps(hashed_backup_codes)
            db.session.commit()
            
            logger.info(f"MFA enabled for user: {user.username}")
            return render_template('mfa_success.html', backup_codes=backup_codes)
        else:
            logger.warning(f"Failed MFA setup verification for user: {user.username}")
            return render_template('setup_mfa.html', 
                                  error="Invalid verification code",
                                  secret=user.totp_secret,
                                  qr_code=generate_qr_code(user.username, user.totp_secret))
    
    # Generate a new TOTP secret
    totp_secret = pyotp.random_base32()
    user.totp_secret = totp_secret
    db.session.commit()
    
    # Generate QR code
    qr_code = generate_qr_code(user.username, totp_secret)
    
    return render_template('setup_mfa.html', secret=totp_secret, qr_code=qr_code)

def generate_qr_code(username, secret):
    """Generate QR code for TOTP setup"""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="Secure MFA App"
    )
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

@app.route('/disable-mfa', methods=['GET', 'POST'])
def disable_mfa():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(id=session['user_id']).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    if not user.mfa_enabled:
        return redirect(url_for('index', message="MFA is not enabled"))
    
    if request.method == 'POST':
        verification_code = request.form.get('verification_code', '').strip()
        password = request.form.get('password', '')
        
        # Verify password first
        try:
            ph.verify(user.password, password)
        except Exception:
            return render_template('disable_mfa.html', error="Invalid password")
        
        # Verify TOTP code
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(verification_code):
            # Disable MFA
            user.mfa_enabled = False
            user.totp_secret = None
            user.backup_codes = None
            db.session.commit()
            
            logger.info(f"MFA disabled for user: {user.username}")
            return redirect(url_for('index', message="MFA has been disabled"))
        else:
            logger.warning(f"Failed MFA disable attempt for user: {user.username}")
            return render_template('disable_mfa.html', error="Invalid verification code")
    
    return render_template('disable_mfa.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login', message="You have been logged out"))

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(id=session['user_id']).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Verify current password
        try:
            ph.verify(user.password, current_password)
        except Exception:
            return render_template('change_password.html', error="Current password is incorrect")
        
        # Validate new password
        if new_password != confirm_password:
            return render_template('change_password.html', error="New passwords do not match")
        
        if not is_strong_password(new_password):
            return render_template('change_password.html', 
                                  error="Password must be at least 12 characters with uppercase, lowercase, numbers, and special characters")
        
        # Update password
        try:
            user.password = ph.hash(new_password)
            db.session.commit()
            
            logger.info(f"Password changed for user: {user.username}")
            return redirect(url_for('index', message="Password has been changed successfully"))
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error changing password: {str(e)}")
            return render_template('change_password.html', error="Failed to change password. Please try again.")
    
    return render_template('change_password.html')

@app.route('/generate-new-backup-codes', methods=['GET', 'POST'])
def generate_new_backup_codes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(id=session['user_id']).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    if not user.mfa_enabled:
        return redirect(url_for('index', message="MFA is not enabled"))
    
    if request.method == 'POST':
        verification_code = request.form.get('verification_code', '').strip()
        password = request.form.get('password', '')
        
        # Verify password first
        try:
            ph.verify(user.password, password)
        except Exception:
            return render_template('new_backup_codes.html', error="Invalid password")
        
        # Verify TOTP code
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(verification_code):
            # Generate new backup codes
            backup_codes, hashed_backup_codes = generate_backup_codes()
            
            # Update backup codes
            user.backup_codes = json.dumps(hashed_backup_codes)
            db.session.commit()
            
            logger.info(f"New backup codes generated for user: {user.username}")
            return render_template('backup_codes_display.html', backup_codes=backup_codes)
        else:
            logger.warning(f"Failed backup code generation attempt for user: {user.username}")
            return render_template('new_backup_codes.html', error="Invalid verification code")
    
    return render_template('new_backup_codes.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal server error: {str(e)}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # In production, use a WSGI server like Gunicorn with HTTPS
    app.run(debug=False)
