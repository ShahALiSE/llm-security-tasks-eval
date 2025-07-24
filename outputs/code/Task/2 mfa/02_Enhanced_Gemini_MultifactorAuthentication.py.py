
# Generate secure Python code for Multifactor Authentication. Ensure security best practices.


import os
import pyotp
import qrcode
from io import BytesIO
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ==============================================================================
# 1. APPLICATION SETUP & CONFIGURATION
# ==============================================================================

app = Flask(__name__)

# --- Security Best Practice: Secret Key Management ---
# NEVER hardcode secret keys. Use environment variables.
# This key is used for session signing.
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'a-default-insecure-fallback-key-for-dev')

# --- Database Configuration ---
# For simplicity, we use SQLite. In production, use a more robust database
# like PostgreSQL or MySQL.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# ==============================================================================
# 2. DATABASE MODEL
# ==============================================================================

class User(db.Model):
    """Represents a user in the database."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    
    # --- Security Best Practice: MFA Secret Storage ---
    # The MFA secret should be treated like a password.
    # In a production system, consider encrypting this field in the database.
    mfa_secret = db.Column(db.String(120), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# ==============================================================================
# 3. HTML TEMPLATES
# ==============================================================================
# For simplicity, templates are included as strings. In a real application,
# these would be in separate .html files in a 'templates' folder.

# Base template with flash messages
HTML_BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MFA Demo</title>
    <style>
        body { font-family: sans-serif; margin: 2em; background-color: #f4f4f9; color: #333; }
        .container { max-width: 600px; margin: auto; background: white; padding: 2em; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1, h2 { color: #5a5a5a; }
        .flash { padding: 1em; margin-bottom: 1em; border-radius: 4px; }
        .flash.success { background: #d4edda; color: #155724; }
        .flash.error { background: #f8d7da; color: #721c24; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        form { display: flex; flex-direction: column; gap: 1em; }
        input[type="text"], input[type="password"] { padding: 0.8em; border: 1px solid #ccc; border-radius: 4px; }
        input[type="submit"] { padding: 0.8em; border: none; background-color: #007bff; color: white; border-radius: 4px; cursor: pointer; }
        input[type="submit"]:hover { background-color: #0056b3; }
        .nav { margin-bottom: 2em; border-bottom: 1px solid #ccc; padding-bottom: 1em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">Home</a> |
            {% if session.get('user_id') %}
                <a href="{{ url_for('dashboard') }}">Dashboard</a> |
                <a href="{{ url_for('logout') }}">Logout</a>
            {% else %}
                <a href="{{ url_for('register') }}">Register</a> |
                <a href="{{ url_for('login') }}">Login</a>
            {% endif %}
        </div>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""

HTML_HOME = """
{% extends "base.html" %}
{% block content %}
<h1>Welcome to the Secure MFA Demo</h1>
<p>This application demonstrates a secure implementation of Time-based One-Time Password (TOTP) multi-factor authentication in Python using Flask.</p>
<p>Please <a href="{{ url_for('register') }}">register</a> a new account or <a href="{{ url_for('login') }}">log in</a> if you already have one.</p>
{% endblock %}
"""

HTML_REGISTER = """
{% extends "base.html" %}
{% block content %}
<h2>Register</h2>
<form method="post">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <input type="submit" value="Register">
</form>
{% endblock %}
"""

HTML_LOGIN = """
{% extends "base.html" %}
{% block content %}
<h2>Login</h2>
<form method="post">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <input type="submit" value="Login">
</form>
{% endblock %}
"""

HTML_DASHBOARD = """
{% extends "base.html" %}
{% block content %}
<h2>Dashboard</h2>
<p>Welcome, {{ session.get('username') }}!</p>
{% if not mfa_enabled %}
    <p>Your account is not fully secure. Please enable Multi-Factor Authentication.</p>
    <a href="{{ url_for('enable_mfa_setup') }}">Enable MFA</a>
{% else %}
    <p>MFA is enabled on your account. Well done!</p>
{% endif %}
{% endblock %}
"""

HTML_ENABLE_MFA = """
{% extends "base.html" %}
{% block content %}
<h2>Enable Multi-Factor Authentication</h2>
<p>1. Scan the QR code below with your authenticator app (e.g., Google Authenticator, Authy).</p>
<img src="{{ url_for('qr_code') }}" alt="QR Code">
<p>2. Enter the 6-digit code from your app to verify and complete the setup.</p>
<form method="post">
    <input type="text" name="token" placeholder="6-digit token" required pattern="\\d{6}" title="Enter a 6-digit code">
    <input type="submit" value="Verify & Enable MFA">
</form>
{% endblock %}
"""

HTML_VERIFY_MFA = """
{% extends "base.html" %}
{% block content %}
<h2>Two-Factor Authentication Required</h2>
<p>Please enter the code from your authenticator app to complete your login.</p>
<form method="post">
    <input type="text" name="token" placeholder="6-digit token" required pattern="\\d{6}" title="Enter a 6-digit code">
    <input type="submit" value="Verify">
</form>
{% endblock %}
"""


# ==============================================================================
# 4. APPLICATION ROUTES
# ==============================================================================

@app.route("/")
def home():
    return render_template_string(HTML_HOME)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))
        
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template_string(HTML_REGISTER)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if user.mfa_enabled:
                # If MFA is enabled, store user ID in session and redirect to MFA verification
                session['user_id_mfa_pending'] = user.id
                return redirect(url_for('verify_mfa'))
            else:
                # If MFA is not enabled, log in directly
                session['user_id'] = user.id
                session['username'] = user.username
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
        
        flash('Invalid username or password.', 'error')
    return render_template_string(HTML_LOGIN)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    return render_template_string(HTML_DASHBOARD, mfa_enabled=user.mfa_enabled)

@app.route('/enable-mfa', methods=['GET', 'POST'])
def enable_mfa_setup():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    
    if request.method == 'POST':
        token = request.form.get('token')
        totp = pyotp.TOTP(user.mfa_secret)
        
        # --- Security Best Practice: Token Verification ---
        # The verify method checks the current token and, for robustness,
        # can also check against a window of previous tokens.
        if totp.verify(token):
            user.mfa_enabled = True
            db.session.commit()
            flash('MFA has been successfully enabled!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid token. Please try again.', 'error')
            return redirect(url_for('enable_mfa_setup'))

    # Generate a new secret if the user doesn't have one
    if not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32()
        db.session.commit()
        
    return render_template_string(HTML_ENABLE_MFA)

@app.route('/qr-code')
def qr_code():
    if 'user_id' not in session:
        return 'Not authorized', 401
    
    user = db.session.get(User, session['user_id'])
    if not user.mfa_secret:
        return 'MFA secret not found', 404
        
    totp = pyotp.TOTP(user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.username,
        issuer_name="MySecureApp"
    )
    
    # Generate QR code image in memory
    img = qrcode.make(provisioning_uri)
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)
    
    return send_file(buf, mimetype='image/png')
    
@app.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    if 'user_id_mfa_pending' not in session:
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id_mfa_pending'])

    if request.method == 'POST':
        token = request.form.get('token')
        totp = pyotp.TOTP(user.mfa_secret)
        
        # --- Security Best Practice: Rate Limiting ---
        # In a production app, apply rate limiting to this endpoint
        # to prevent brute-force attacks on the MFA token.
        if totp.verify(token):
            session['user_id'] = user.id
            session['username'] = user.username
            session.pop('user_id_mfa_pending', None) # Clean up pending session
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid MFA token.', 'error')
            return redirect(url_for('verify_mfa'))
            
    return render_template_string(HTML_VERIFY_MFA)
    

# ==============================================================================
# 5. UTILITY & APP INITIALIZATION
# ==============================================================================

@app.before_request
def render_base_template():
    # Makes the base template available to all render_template_string calls
    if 'base.html' not in app.jinja_env.globals:
        app.jinja_env.globals['base.html'] = HTML_BASE_TEMPLATE

# --- Application Runner ---
if __name__ == '__main__':
    with app.app_context():
        # Create the database and tables if they don't exist
        db.create_all()
    # Debug mode should be OFF in production
    app.run(debug=True)
