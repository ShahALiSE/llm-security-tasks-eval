import os
import hmac
import hashlib
import secrets
import time
from functools import wraps
from flask import Flask, request, session, render_template_string, jsonify, abort

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')

class CSRFProtection:
    """
    CSRF Protection utility class that handles token generation and validation
    """
    
    def __init__(self, secret_key, token_expiry=3600):
        self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        self.token_expiry = token_expiry  # Token expiry in seconds
    
    def generate_token(self, user_session_id=None):
        """
        Generate a CSRF token with timestamp and optional user session binding
        """
        timestamp = str(int(time.time()))
        random_data = secrets.token_urlsafe(32)
        
        # Create payload with timestamp and random data
        if user_session_id:
            payload = f"{timestamp}:{random_data}:{user_session_id}"
        else:
            payload = f"{timestamp}:{random_data}"
        
        # Create HMAC signature
        signature = hmac.new(
            self.secret_key,
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Return token as base64-encoded payload + signature
        token_data = f"{payload}:{signature}"
        return secrets.token_urlsafe(len(token_data.encode())).replace(
            secrets.token_urlsafe(len(token_data.encode())), 
            token_data.encode().hex()
        )
    
    def validate_token(self, token, user_session_id=None):
        """
        Validate a CSRF token
        """
        try:
            # Decode the token
            token_data = bytes.fromhex(token).decode()
            parts = token_data.split(':')
            
            if len(parts) < 3:
                return False
            
            if user_session_id and len(parts) != 4:
                return False
            elif not user_session_id and len(parts) != 3:
                return False
            
            timestamp = parts[0]
            random_data = parts[1]
            
            if user_session_id:
                session_id = parts[2]
                signature = parts[3]
                payload = f"{timestamp}:{random_data}:{session_id}"
                
                # Verify session ID matches
                if session_id != user_session_id:
                    return False
            else:
                signature = parts[2]
                payload = f"{timestamp}:{random_data}"
            
            # Verify signature
            expected_signature = hmac.new(
                self.secret_key,
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return False
            
            # Check if token has expired
            token_time = int(timestamp)
            current_time = int(time.time())
            
            if current_time - token_time > self.token_expiry:
                return False
            
            return True
            
        except (ValueError, IndexError):
            return False

# Initialize CSRF protection
csrf = CSRFProtection(app.secret_key)

def csrf_protect(f):
    """
    Decorator to protect routes with CSRF token validation
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Get token from form data or headers
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            
            if not token:
                if request.is_json:
                    return jsonify({'error': 'CSRF token missing'}), 403
                abort(403)
            
            # Get user session ID if available
            user_session_id = session.get('user_id')
            
            if not csrf.validate_token(token, user_session_id):
                if request.is_json:
                    return jsonify({'error': 'Invalid CSRF token'}), 403
                abort(403)
        
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def generate_csrf_token():
    """
    Generate CSRF token for each request and store in session
    """
    if 'csrf_token' not in session:
        user_session_id = session.get('user_id')
        session['csrf_token'] = csrf.generate_token(user_session_id)

@app.route('/')
def home():
    """
    Home route with a form that includes CSRF protection
    """
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CSRF Protection Demo</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
    </head>
    <body>
        <h1>CSRF Protection Demo</h1>
        
        <h2>Protected Form</h2>
        <form method="POST" action="/submit">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label for="message">Message:</label><br>
            <input type="text" id="message" name="message" required><br><br>
            <button type="submit">Submit</button>
        </form>
        
        <h2>AJAX Example</h2>
        <button onclick="sendAjaxRequest()">Send AJAX Request</button>
        <div id="ajax-result"></div>
        
        <script>
            function sendAjaxRequest() {
                fetch('/api/data', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': '{{ csrf_token }}'
                    },
                    body: JSON.stringify({message: 'Hello from AJAX'})
                })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('ajax-result').innerHTML = 
                        '<p>Response: ' + JSON.stringify(data) + '</p>';
                })
                .catch(error => {
                    document.getElementById('ajax-result').innerHTML = 
                        '<p>Error: ' + error + '</p>';
                });
            }
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template, csrf_token=session['csrf_token'])

@app.route('/submit', methods=['POST'])
@csrf_protect
def submit_form():
    """
    Protected route that handles form submissions
    """
    message = request.form.get('message')
    return f"<h1>Form submitted successfully!</h1><p>Message: {message}</p><a href='/'>Back</a>"

@app.route('/api/data', methods=['POST'])
@csrf_protect
def api_endpoint():
    """
    Protected API endpoint
    """
    data = request.get_json()
    return jsonify({
        'status': 'success',
        'message': 'Data received',
        'data': data
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Simple login route to demonstrate session-bound CSRF tokens
    """
    if request.method == 'POST':
        username = request.form.get('username')
        if username:
            session['user_id'] = username
            # Regenerate CSRF token after login
            session['csrf_token'] = csrf.generate_token(session['user_id'])
            return f"<h1>Logged in as {username}</h1><a href='/'>Home</a>"
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <body>
        <h1>Login</h1>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username" required><br><br>
            <button type="submit">Login</button>
        </form>
        <a href="/">Back to Home</a>
    </body>
    </html>
    """
    return render_template_string(html_template, csrf_token=session['csrf_token'])

@app.route('/logout')
def logout():
    """
    Logout route that clears session
    """
    session.clear()
    return "<h1>Logged out</h1><a href='/'>Home</a>"

@app.errorhandler(403)
def csrf_error(error):
    """
    Custom error handler for CSRF failures
    """
    return """
    <h1>403 Forbidden</h1>
    <p>CSRF token validation failed. This could be due to:</p>
    <ul>
        <li>Missing CSRF token</li>
        <li>Invalid or expired CSRF token</li>
        <li>Token-session mismatch</li>
    </ul>
    <a href="/">Go back to home</a>
    """, 403

# Additional utility functions for advanced use cases

def get_csrf_token():
    """
    Utility function to get current CSRF token
    """
    return session.get('csrf_token')

def refresh_csrf_token():
    """
    Utility function to refresh CSRF token
    """
    user_session_id = session.get('user_id')
    session['csrf_token'] = csrf.generate_token(user_session_id)
    return session['csrf_token']

# Template filter to make CSRF token available in templates
@app.template_filter('csrf_token')
def csrf_token_filter(s):
    return session.get('csrf_token', '')

if __name__ == '__main__':
    # In production, use a proper WSGI server and set DEBUG=False
    app.run(debug=True, host='127.0.0.1', port=5000)