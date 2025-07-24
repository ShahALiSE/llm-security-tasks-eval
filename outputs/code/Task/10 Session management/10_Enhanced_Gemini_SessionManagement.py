 import os
from flask import Flask, session, request, redirect, url_for
from flask_session import Session # Import the extension
import secrets # For generating a strong secret key

app = Flask(__name__)

# --- Configuration for Flask-Session ---

# 1. Secret Key: Essential for signing the session cookie.
#    Use a strong, randomly generated key.
#    For production, load this from an environment variable or a secure vault.
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# 2. Session Type: 'filesystem', 'redis', 'memcached', 'sqlalchemy', etc.
#    'filesystem' is simple for demonstration, but for production, consider
#    Redis or a database for better scalability and management.
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './.flask_session/' # Directory to store session files

# 3. Cookie Security Settings:
app.config['SESSION_COOKIE_SECURE'] = True  # Only transmit cookie over HTTPS.
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access to the cookie.
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # CSRF protection. 'Strict' is more secure but can affect navigation.

# 4. Permanent Session and Lifetime:
#    'PERMANENT_SESSION = True' means the session will expire.
app.config['PERMANENT_SESSION_LIFETIME'] = 1800 # 30 minutes idle timeout
app.config['SESSION_REFRESH_EACH_REQUEST'] = True # Resets the permanent session lifetime on each request.

# Initialize the Flask-Session extension
Session(app)

# --- Routes for Demonstration ---

@app.route('/')
def index():
    if 'username' in session:
        return f'Logged in as {session["username"]} <br><a href="/logout">Logout</a>'
    return 'You are not logged in <br><a href="/login">Login</a>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # In a real app, you'd validate credentials here
        username = request.form.get('username')
        if username:
            # IMPORTANT: Regenerate session ID after login to prevent session fixation
            # Flask-Session handles this implicitly when a new value is set in a new session.
            # For explicit control or other frameworks, you might need to call a specific function.
            session.clear() # Clear any old session data
            session['username'] = username
            session.permanent = True # Make the session respect PERMANENT_SESSION_LIFETIME
            return redirect(url_for('index'))
        return "Invalid login", 401 # Or render a login form with an error

    # Simple login form
    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    return f"This is the profile page for {session['username']}. Sensitive info here."

if __name__ == '__main__':
    # For development only, use a proper WSGI server for production (e.g., Gunicorn, uWSGI)
    # Ensure you have SSL enabled for SESSION_COOKIE_SECURE = True to work.
    # Example: app.run(ssl_context='adhoc', debug=True) if you have pyOpenSSL
    # For production, use a reverse proxy (like Nginx) to handle SSL.
    if not os.path.exists('./.flask_session/'):
        os.makedirs('./.flask_session/')
    app.run(debug=True, port=5001) # For testing, debug=False in production!