import os
from flask import Flask, request, make_response, render_template_string, g, abort

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management

# HTML templates
LOGIN_FORM = """
<h1>Login</h1>
<form action="/login" method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <input type="text" name="username" placeholder="Username"><br>
    <input type="password" name="password" placeholder="Password"><br>
    <button type="submit">Login</button>
</form>
"""

DASHBOARD = """
<h1>Welcome, {{ username }}!</h1>
<form action="/transfer" method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <input type="text" name="amount" placeholder="Amount"><br>
    <input type="text" name="to_account" placeholder="Recipient"><br>
    <button type="submit">Transfer Money</button>
</form>
<p><a href="/logout">Logout</a></p>
"""

def generate_csrf_token():
    """Generate a secure random CSRF token."""
    return os.urandom(32).hex()

@app.before_request
def csrf_protect():
    """CSRF protection middleware."""
    if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
        # Set CSRF token if not present
        if 'csrf_token' not in request.cookies:
            g.csrf_token = generate_csrf_token()
    else:
        # Verify CSRF token for unsafe methods
        csrf_cookie = request.cookies.get('csrf_token')
        csrf_form = request.form.get('csrf_token')
        
        if not csrf_cookie or csrf_cookie != csrf_form:
            abort(403, "CSRF token verification failed")

@app.after_request
def set_csrf_cookie(response):
    """Set CSRF token in cookie if generated."""
    if hasattr(g, 'csrf_token') and g.csrf_token:
        response.set_cookie(
            'csrf_token',
            g.csrf_token,
            httponly=False,      # Allow JavaScript to read
            samesite='Strict',   # Prevent cross-origin sending
            secure=True          # Require HTTPS in production
        )
    return response

# Session storage (in-memory for demo - use proper sessions in production)
users = {}
sessions = {}

@app.route('/')
def home():
    """Home page with login form."""
    csrf_token = g.get('csrf_token') or request.cookies.get('csrf_token')
    return render_template_string(LOGIN_FORM, csrf_token=csrf_token)

@app.route('/login', methods=['POST'])
def login():
    """Login handler with CSRF protection."""
    username = request.form.get('username')
    password = request.form.get('password')  # In real apps, hash and verify
    
    # Simple authentication (for demo only)
    if username and password:
        session_id = os.urandom(16).hex()
        users[session_id] = username
        resp = make_response(f"Welcome {username}! <a href='/dashboard'>Continue</a>")
        resp.set_cookie('session_id', session_id, httponly=True, secure=True)
        return resp
    return "Invalid credentials", 401

@app.route('/dashboard')
def dashboard():
    """Protected dashboard with sensitive actions."""
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in users:
        return "Unauthorized", 401
    
    csrf_token = g.get('csrf_token') or request.cookies.get('csrf_token')
    return render_template_string(DASHBOARD, 
                                username=users[session_id],
                                csrf_token=csrf_token)

@app.route('/transfer', methods=['POST'])
def transfer():
    """Sensitive action protected by CSRF."""
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in users:
        return "Unauthorized", 401
    
    # CSRF check happens in before_request middleware
    amount = request.form.get('amount')
    to_account = request.form.get('to_account')
    return f"Transfer of ${amount} to {to_account} completed successfully!"

@app.route('/logout')
def logout():
    """Logout handler."""
    session_id = request.cookies.get('session_id')
    if session_id in users:
        del users[session_id]
    resp = make_response("Logged out successfully. <a href='/'>Login again</a>")
    resp.set_cookie('session_id', '', expires=0)
    return resp

if __name__ == '__main__':
    app.run(ssl_context='adhoc', debug=True)  # HTTPS required for secure cookies