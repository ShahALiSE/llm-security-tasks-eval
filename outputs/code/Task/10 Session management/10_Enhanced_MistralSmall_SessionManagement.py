 from flask import Flask, session, redirect, url_for, request, render_template_string
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta
import os

app = Flask(__name__)

# Set a secret key for session management
app.secret_key = os.urandom(24)

# Set the session timeout to 30 minutes
app.permanent_session_lifetime = timedelta(minutes=30)

# Enable CSRF protection
csrf = CSRFProtect(app)

# Configure secure cookie settings
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    REMEMBER_COOKIE_SECURE=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE='Lax'
)

@app.before_request
def before_request():
    session.permanent = True
    if 'last_activity' in session:
        last_activity_time = session['last_activity']
        if datetime.utcnow() - last_activity_time > app.permanent_session_lifetime:
            session.clear()
            return redirect(url_for('logout'))
    session['last_activity'] = datetime.utcnow()

@app.route('/')
def index():
    if 'username' in session:
        return f'Logged in as {session["username"]}'
    return 'You are not logged in'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['username'] = request.form['username']
        return redirect(url_for('index'))
    return render_template_string('''
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            Username: <input type="text" name="username"><br>
            <input type="submit" value="Login">
        </form>
    ''')

@app.route('/logout')
def logout():
    session.clear()
    return 'You are now logged out'

if __name__ == '__main__':
    app.run(ssl_context='adhoc', debug=True)
