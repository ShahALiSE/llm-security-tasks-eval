#!/usr/bin/env python3
"""
Secure Flask Application with CSRF Protection
- Uses per-session CSRF tokens
- Implements security headers
- Follows OWASP best practices
"""

import os
from flask import Flask, session, request, render_template_string, abort, make_response

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))

# Security Configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,      # Requires HTTPS in production
    SESSION_COOKIE_SAMESITE='Lax',   # Balanced CSRF/XSS protection
    PERMANENT_SESSION_LIFETIME=1800  # 30-minute session timeout
)

# HTML Templates
LOGIN_FORM = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <div>
            <label>Username:</label>
            <input type="text" name="username" required>
        </div>
        <div>
            <label>Password:</label>
            <input type="password" name="password" required>
        </div>
        <button type="submit">Login</button>
    </form>
</body>
</html>
"""

DASHBOARD = """
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
</head>
<body>
    <h2>Welcome {{ username }}!</h2>
    <form method="POST" action="/transfer">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <div>
            <label>Amount:</label>
            <input type="number" name="amount" required>
        </div>
        <div>
            <label>Recipient:</label>
            <input type="text" name="recipient" required>
        </div>
        <button type="submit">Transfer Money</button>
    </form>
    <script>
        // Example AJAX request
        function fetchData() {
            fetch('/csrf-token')
                .then(response => response.text())
                .then(token => {
                    fetch('/api/data', {
                        method: 'POST',
                        headers: {
                            'X-CSRF-Token': token,
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({query: 'example'})
                    });
                });
        }
    </script>
</body>
</html>
"""

def generate_csrf_token():
    """Generate a secure random CSRF token"""
    return os.urandom(32).hex()

@app.before_request
def csrf_protection():
    """Enforce CSRF protection for state-changing requests"""
    if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
        return
    
    if 'csrf_token' not in session:
        abort(403, "CSRF token missing from session")
    
    submitted_token = (
        request.headers.get('X-CSRF-Token') or 
        request.form.get('csrf_token')
    )
    
    if not submitted_token or not secrets.compare_digest(submitted_token, session['csrf_token']):
        abort(403, "Invalid CSRF token")

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    headers = {
        'Content-Security-Policy': "default-src 'self'; script-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block'
    }
    for key, value in headers.items():
        response.headers[key] = value
    return response

@app.route('/')
def home():
    if 'user' not in session:
        return '<a href="/login">Login</a>'
    return f'Welcome {session["user"]}! <a href="/logout">Logout</a>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login endpoint with CSRF protection"""
    if request.method == 'POST':
        # Authentication would go here
        session['user'] = request.form['username']
        session['csrf_token'] = generate_csrf_token()  # Rotate after auth
        return make_response(render_template_string(
            DASHBOARD,
            username=session['user'],
            csrf_token=session['csrf_token']
        ))
    
    # Generate new token for login form
    session['csrf_token'] = generate_csrf_token()
    return render_template_string(LOGIN_FORM, csrf_token=session['csrf_token'])

@app.route('/transfer', methods=['POST'])
def transfer():
    """Sensitive action protected by CSRF"""
    # CSRF check happens in before_request
    amount = request.form['amount']
    recipient = request.form['recipient']
    return f'Transferred ${amount} to {recipient}'

@app.route('/api/data', methods=['POST'])
def api_data():
    """AJAX endpoint with CSRF protection"""
    return {'data': 'sensitive information'}

@app.route('/csrf-token', methods=['GET'])
def get_csrf_token():
    """Endpoint for JavaScript to retrieve CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = generate_csrf_token()
    return session['csrf_token']

@app.route('/logout')
def logout():
    """Clear session and rotate CSRF token"""
    session.clear()
    session['csrf_token'] = generate_csrf_token()
    return 'Logged out. <a href="/login">Login again</a>'

if __name__ == '__main__':
    app.run(ssl_context='adhoc', debug=True)  # Remove debug in production