import base64
import os
import hashlib
import hmac
import time
import qrcode
from io import BytesIO
import pyotp
from flask import Flask, request, jsonify, session, render_template_string
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mfa_users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_mfa_secret(self):
        """Generate a new MFA secret for the user."""
        if not self.mfa_secret:
            self.mfa_secret = pyotp.random_base32()
            db.session.commit()
        return self.mfa_secret
    
    def verify_totp(self, token):
        """Verify a TOTP token against the user's secret."""
        if not self.mfa_secret:
            return False
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(token)

def create_tables():
    with app.app_context():
        db.create_all()

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password'}), 400
    
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        return jsonify({'message': 'Username already exists'}), 409
    
    new_user = User(username=data['username'])
    new_user.set_password(data['password'])
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid username or password'}), 401
    
    # If MFA is enabled, require the token
    if user.mfa_enabled:
        if not data.get('token'):
            return jsonify({
                'message': 'MFA token required',
                'require_mfa': True
            }), 401

        if not user.verify_totp(data['token']):
            return jsonify({'message': 'Invalid MFA token'}), 401
    
    # Set up the session
    session['user_id'] = user.id
    session['authenticated'] = True
    
    return jsonify({
        'message': 'Login successful',
        'mfa_enabled': user.mfa_enabled
    })

@app.route('/mfa/setup', methods=['GET'])
def setup_mfa():
    if 'user_id' not in session:
        return jsonify({'message': 'Authentication required'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Generate a new secret if needed
    secret = user.generate_mfa_secret()
    
    # Create a provisioning URI for the QR code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(user.username, issuer_name="MFA Demo App")
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert image to base64 for displaying in HTML
    buffer = BytesIO()
    img.save(buffer)
    img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    return jsonify({
        'secret': secret,
        'qr_code': f"data:image/png;base64,{img_str}"
    })

@app.route('/mfa/verify', methods=['POST'])
def verify_mfa():
    if 'user_id' not in session:
        return jsonify({'message': 'Authentication required'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    data = request.get_json()
    if not data or not data.get('token'):
        return jsonify({'message': 'MFA token required'}), 400
    
    # Verify the token
    if user.verify_totp(data['token']):
        user.mfa_enabled = True
        db.session.commit()
        return jsonify({'message': 'MFA enabled successfully'})
    else:
        return jsonify({'message': 'Invalid MFA token'}), 401

@app.route('/mfa/disable', methods=['POST'])
def disable_mfa():
    if 'user_id' not in session:
        return jsonify({'message': 'Authentication required'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    data = request.get_json()
    
    # For disabling, we should require both the password and a valid MFA token for security
    if not data or not data.get('password') or not data.get('token'):
        return jsonify({'message': 'Password and MFA token required'}), 400
    
    if not user.check_password(data['password']) or not user.verify_totp(data['token']):
        return jsonify({'message': 'Invalid password or MFA token'}), 401
    
    user.mfa_enabled = False
    # Optionally, reset the secret to force re-enrollment if they enable again
    user.mfa_secret = None
    db.session.commit()
    
    return jsonify({'message': 'MFA disabled successfully'})

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    session.pop('authenticated', None)
    return jsonify({'message': 'Logged out successfully'})

@app.route('/')
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MFA Demo</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .container { margin-top: 20px; }
            .hidden { display: none; }
            input, button { margin: 10px 0; padding: 8px; }
            button { cursor: pointer; background-color: #4CAF50; color: white; border: none; }
            button:hover { background-color: #45a049; }
            #qrcode { margin-top: 20px; }
        </style>
    </head>
    <body>
        <h1>Multifactor Authentication Demo</h1>
        
        <div id="login-container">
            <h2>Login</h2>
            <input type="text" id="username" placeholder="Username"><br>
            <input type="password" id="password" placeholder="Password"><br>
            <div id="mfa-input" class="hidden">
                <input type="text" id="mfa-token" placeholder="MFA Code"><br>
            </div>
            <button onclick="login()">Login</button>
        </div>
        
        <div id="register-container">
            <h2>Register</h2>
            <input type="text" id="reg-username" placeholder="Username"><br>
            <input type="password" id="reg-password" placeholder="Password"><br>
            <button onclick="register()">Register</button>
        </div>
        
        <div id="mfa-setup-container" class="hidden">
            <h2>Setup MFA</h2>
            <p>Scan the QR code with your authenticator app:</p>
            <div id="qrcode"></div>
            <p>Or enter this code manually: <span id="secret-key"></span></p>
            <input type="text" id="verify-token" placeholder="Enter code from app"><br>
            <button onclick="verifyAndEnableMFA()">Verify and Enable MFA</button>
        </div>
        
        <div id="user-container" class="hidden">
            <h2>Welcome <span id="user-greeting"></span>!</h2>
            <button onclick="setupMFA()">Setup MFA</button>
            <button onclick="disableMFA()" id="disable-mfa-btn" class="hidden">Disable MFA</button>
            <button onclick="logout()">Logout</button>
        </div>
        
        <script>
            let currentUser = null;
            
            async function login() {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const mfaToken = document.getElementById('mfa-token').value;
                
                const data = {
                    username: username,
                    password: password
                };
                
                if (mfaToken) {
                    data.token = mfaToken;
                }
                
                try {
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });
                    
                    const result = await response.json();
                    
                    if (response.ok) {
                        currentUser = username;
                        document.getElementById('user-greeting').textContent = username;
                        document.getElementById('login-container').classList.add('hidden');
                        document.getElementById('register-container').classList.add('hidden');
                        document.getElementById('user-container').classList.remove('hidden');
                        
                        if (result.mfa_enabled) {
                            document.getElementById('disable-mfa-btn').classList.remove('hidden');
                        } else {
                            document.getElementById('disable-mfa-btn').classList.add('hidden');
                        }
                    } else if (result.require_mfa) {
                        document.getElementById('mfa-input').classList.remove('hidden');
                        alert('Please enter your MFA code');
                    } else {
                        alert(result.message || 'Login failed');
                    }
                } catch (error) {
                    console.error('Error:', error);
                    alert('An error occurred during login');
                }
            }
            
            async function register() {
                const username = document.getElementById('reg-username').value;
                const password = document.getElementById('reg-password').value;
                
                try {
                    const response = await fetch('/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });
                    
                    const result = await response.json();
                    
                    if (response.ok) {
                        alert('Registration successful! You can now login.');
                    } else {
                        alert(result.message || 'Registration failed');
                    }
                } catch (error) {
                    console.error('Error:', error);
                    alert('An error occurred during registration');
                }
            }
            
            async function setupMFA() {
                try {
                    const response = await fetch('/mfa/setup');
                    
                    if (response.ok) {
                        const result = await response.json();
                        document.getElementById('qrcode').innerHTML = `<img src="${result.qr_code}" alt="QR Code">`;
                        document.getElementById('secret-key').textContent = result.secret;
                        document.getElementById('mfa-setup-container').classList.remove('hidden');
                    } else {
                        const result = await response.json();
                        alert(result.message || 'Failed to setup MFA');
                    }
                } catch (error) {
                    console.error('Error:', error);
                    alert('An error occurred during MFA setup');
                }
            }
            
            async function verifyAndEnableMFA() {
                const token = document.getElementById('verify-token').value;
                
                try {
                    const response = await fetch('/mfa/verify', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token })
                    });
                    
                    const result = await response.json();
                    
                    if (response.ok) {
                        alert('MFA has been successfully enabled!');
                        document.getElementById('mfa-setup-container').classList.add('hidden');
                        document.getElementById('disable-mfa-btn').classList.remove('hidden');
                    } else {
                        alert(result.message || 'Failed to verify MFA token');
                    }
                } catch (error) {
                    console.error('Error:', error);
                    alert('An error occurred during MFA verification');
                }
            }
            
            async function disableMFA() {
                const password = prompt('Please enter your password:');
                const token = prompt('Please enter your MFA code:');
                
                if (!password || !token) {
                    return;
                }
                
                try {
                    const response = await fetch('/mfa/disable', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password, token })
                    });
                    
                    const result = await response.json();
                    
                    if (response.ok) {
                        alert('MFA has been disabled');
                        document.getElementById('disable-mfa-btn').classList.add('hidden');
                    } else {
                        alert(result.message || 'Failed to disable MFA');
                    }
                } catch (error) {
                    console.error('Error:', error);
                    alert('An error occurred while disabling MFA');
                }
            }
            
            async function logout() {
                try {
                    const response = await fetch('/logout', { method: 'POST' });
                    
                    if (response.ok) {
                        currentUser = null;
                        document.getElementById('username').value = '';
                        document.getElementById('password').value = '';
                        document.getElementById('mfa-token').value = '';
                        document.getElementById('mfa-input').classList.add('hidden');
                        document.getElementById('login-container').classList.remove('hidden');
                        document.getElementById('register-container').classList.remove('hidden');
                        document.getElementById('user-container').classList.add('hidden');
                        document.getElementById('mfa-setup-container').classList.add('hidden');
                    } else {
                        const result = await response.json();
                        alert(result.message || 'Logout failed');
                    }
                } catch (error) {
                    console.error('Error:', error);
                    alert('An error occurred during logout');
                }
            }
        </script>
    </body>
    </html>
    """)

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)
