import secrets
import hmac
import hashlib
import time
from functools import wraps
from typing import Optional, Dict, Any
from flask import Flask, request, session, render_template_string, jsonify, abort

class CSRFProtection:
    """
    Secure CSRF Protection implementation with token generation and validation.
    """
    
    def __init__(self, secret_key: str, token_expiry: int = 3600):
        """
        Initialize CSRF protection.
        
        Args:
            secret_key: Secret key for HMAC signing (should be cryptographically secure)
            token_expiry: Token expiration time in seconds (default: 1 hour)
        """
        if len(secret_key) < 32:
            raise ValueError("Secret key must be at least 32 characters long")
        
        self.secret_key = secret_key.encode('utf-8')
        self.token_expiry = token_expiry
    
    def generate_token(self, session_id: str) -> str:
        """
        Generate a cryptographically secure CSRF token.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Base64-encoded CSRF token
        """
        # Generate random nonce
        nonce = secrets.token_bytes(16)
        
        # Current timestamp
        timestamp = int(time.time())
        
        # Create payload: nonce + timestamp + session_id
        payload = nonce + timestamp.to_bytes(8, 'big') + session_id.encode('utf-8')
        
        # Generate HMAC signature
        signature = hmac.new(
            self.secret_key,
            payload,
            hashlib.sha256
        ).digest()
        
        # Combine payload and signature
        token_bytes = payload + signature
        
        # Return base64-encoded token
        import base64
        return base64.urlsafe_b64encode(token_bytes).decode('ascii')
    
    def validate_token(self, token: str, session_id: str) -> bool:
        """
        Validate a CSRF token.
        
        Args:
            token: The CSRF token to validate
            session_id: Current session identifier
            
        Returns:
            True if token is valid, False otherwise
        """
        try:
            import base64
            
            # Decode the token
            token_bytes = base64.urlsafe_b64decode(token.encode('ascii'))
            
            # Extract components
            if len(token_bytes) < 56:  # 16 (nonce) + 8 (timestamp) + 32 (signature) minimum
                return False
            
            nonce = token_bytes[:16]
            timestamp_bytes = token_bytes[16:24]
            session_data = token_bytes[24:-32]
            provided_signature = token_bytes[-32:]
            
            # Reconstruct payload
            payload = nonce + timestamp_bytes + session_data
            
            # Verify HMAC signature
            expected_signature = hmac.new(
                self.secret_key,
                payload,
                hashlib.sha256
            ).digest()
            
            # Constant-time comparison to prevent timing attacks
            if not hmac.compare_digest(provided_signature, expected_signature):
                return False
            
            # Check session ID
            if session_data.decode('utf-8') != session_id:
                return False
            
            # Check token expiration
            timestamp = int.from_bytes(timestamp_bytes, 'big')
            if time.time() - timestamp > self.token_expiry:
                return False
            
            return True
            
        except Exception:
            # Any exception during validation means invalid token
            return False
    
    def get_token_for_session(self, session_dict: Dict[str, Any]) -> str:
        """
        Get or generate CSRF token for the current session.
        
        Args:
            session_dict: Flask session dictionary
            
        Returns:
            CSRF token string
        """
        # Ensure session has an ID
        if 'csrf_session_id' not in session_dict:
            session_dict['csrf_session_id'] = secrets.token_urlsafe(32)
        
        # Generate new token for each request (stateless approach)
        return self.generate_token(session_dict['csrf_session_id'])


# Flask application setup
app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)  # Generate secure secret key

# Initialize CSRF protection
csrf = CSRFProtection(
    secret_key=secrets.token_urlsafe(32),  # Use a strong secret key
    token_expiry=3600  # 1 hour expiration
)

def csrf_protect(f):
    """
    Decorator to protect routes with CSRF validation.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Get token from form data or headers
            token = (
                request.form.get('csrf_token') or 
                request.headers.get('X-CSRF-Token') or
                request.json.get('csrf_token') if request.is_json else None
            )
            
            if not token:
                abort(403, description="CSRF token missing")
            
            # Validate token
            session_id = session.get('csrf_session_id', '')
            if not csrf.validate_token(token, session_id):
                abort(403, description="CSRF token invalid")
        
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_csrf_token():
    """
    Make CSRF token available in all templates.
    """
    return dict(csrf_token=csrf.get_token_for_session(session))

# Example routes
@app.route('/')
def index():
    """
    Display a form with CSRF protection.
    """
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>CSRF Protection Demo</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
    </head>
    <body>
        <h1>CSRF Protection Demo</h1>
        
        <h2>Form Submission</h2>
        <form method="POST" action="/submit">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
            <br><br>
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required>
            <br><br>
            <button type="submit">Submit Form</button>
        </form>
        
        <h2>AJAX Request</h2>
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
                body: JSON.stringify({
                    message: 'Hello from AJAX'
                })
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('ajax-result').innerHTML = 
                    '<p>AJAX Response: ' + JSON.stringify(data) + '</p>';
            })
            .catch(error => {
                document.getElementById('ajax-result').innerHTML = 
                    '<p>Error: ' + error.message + '</p>';
            });
        }
        </script>
    </body>
    </html>
    '''
    return render_template_string(template)

@app.route('/submit', methods=['POST'])
@csrf_protect
def submit_form():
    """
    Handle form submission with CSRF protection.
    """
    username = request.form.get('username')
    email = request.form.get('email')
    
    return f'''
    <h1>Form Submitted Successfully!</h1>
    <p>Username: {username}</p>
    <p>Email: {email}</p>
    <a href="/">Back to form</a>
    '''

@app.route('/api/data', methods=['POST'])
@csrf_protect
def api_endpoint():
    """
    API endpoint with CSRF protection.
    """
    data = request.get_json()
    return jsonify({
        'status': 'success',
        'message': 'Data received',
        'received_data': data
    })

@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    """
    Endpoint to get a fresh CSRF token for AJAX requests.
    """
    return jsonify({
        'csrf_token': csrf.get_token_for_session(session)
    })

# Error handler for CSRF failures
@app.errorhandler(403)
def handle_csrf_error(error):
    """
    Handle CSRF validation errors.
    """
    if request.is_json:
        return jsonify({
            'error': 'CSRF protection failed',
            'message': str(error.description)
        }), 403
    else:
        return f'''
        <h1>CSRF Protection Error</h1>
        <p>{error.description}</p>
        <p>This usually happens when:</p>
        <ul>
            <li>The CSRF token is missing from your request</li>
            <li>The CSRF token has expired</li>
            <li>The CSRF token is invalid</li>
        </ul>
        <a href="/">Return to main page</a>
        ''', 403

if __name__ == '__main__':
    # Security best practices for production:
    # - Use environment variables for secret keys
    # - Enable HTTPS only
    # - Set secure session cookies
    # - Use a production WSGI server
    
    app.config.update(
        SESSION_COOKIE_SECURE=True,  # HTTPS only
        SESSION_COOKIE_HTTPONLY=True,  # No JavaScript access
        SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
    )
    
    print("CSRF Protection Demo Server")
    print("Visit http://localhost:5000 to test")
    print("\nSecurity Features:")
    print("- Cryptographically secure token generation")
    print("- HMAC-based token validation")
    print("- Token expiration (1 hour)")
    print("- Constant-time comparison")
    print("- Support for forms and AJAX")
    
    app.run(debug=True, host='localhost', port=5000)