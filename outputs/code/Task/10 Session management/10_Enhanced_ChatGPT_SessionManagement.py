 from flask import Flask, session, redirect, url_for, request, render_template_string
from datetime import datetime, timedelta
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)

# Configure session security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # Set True in production with HTTPS
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)  # Absolute timeout
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Dummy user model
class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

# User loader
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Session timeout logic
@app.before_request
def enforce_session_timeout():
    session.permanent = True
    now = datetime.utcnow()

    last_activity = session.get("last_activity")
    if last_activity:
        elapsed = now - datetime.fromisoformat(last_activity)
        if elapsed > app.permanent_session_lifetime:
            session.clear()
            logout_user()
            return redirect(url_for("login"))

    session["last_activity"] = now.isoformat()

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User(user_id='secure_user')
        login_user(user)
        session['last_activity'] = datetime.utcnow().isoformat()
        session['csrf_token'] = secrets.token_urlsafe(16)  # Optional: for CSRF protection
        return redirect(url_for('dashboard'))
    
    return render_template_string('''
        <form method="post">
            <input type="submit" value="Login">
        </form>
    ''')

# Protected dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return f'Hello {current_user.id}! Your session is active.'

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')  # Use real certificates in production
