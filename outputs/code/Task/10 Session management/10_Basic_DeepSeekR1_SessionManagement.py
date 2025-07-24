from flask import Flask, session, redirect, url_for, request, render_template, jsonify
from datetime import timedelta, datetime
import os
import secrets

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # Default session lifetime
    SESSION_TIMEOUT=15*60,  # 15 minutes of inactivity timeout (in seconds)
    SESSION_COOKIE_SECURE=True,  # Requires HTTPS in production
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# In-memory session storage (replace with Redis/DB in production)
sessions = {}

@app.before_request
def manage_sessions():
    """Handle session validation and timeout before each request"""
    # Skip session checks for static files and login page
    if request.endpoint in ['static', 'login']:
        return
    
    session_id = session.get('session_id')
    current_time = datetime.now()
    
    # Validate existing session
    if session_id and session_id in sessions:
        session_data = sessions[session_id]
        
        # Check session expiration
        if session_data['expiry'] <= current_time:
            session.clear()
            sessions.pop(session_id, None)
            return redirect(url_for('login', reason='expired'))
        
        # Check inactivity timeout
        if (current_time - session_data['last_activity']).total_seconds() > app.config['SESSION_TIMEOUT']:
            session.clear()
            sessions.pop(session_id, None)
            return redirect(url_for('login', reason='inactive'))
        
        # Update activity timestamp
        session_data['last_activity'] = current_time
        sessions[session_id] = session_data
        session.modified = True
        
    else:
        # No valid session - redirect to login
        return redirect(url_for('login', reason='unauthorized'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with session creation"""
    if request.method == 'POST':
        # Authentication logic (replace with your actual authentication)
        username = request.form.get('username')
        password = request.form.get('password')
        
        if authenticate_user(username, password):  # Implement your auth logic
            return create_new_session(username)
        
        return render_template('login.html', error='Invalid credentials')
    
    # Handle redirect reasons
    reason = request.args.get('reason')
    message = ''
    if reason == 'expired':
        message = 'Session expired. Please login again.'
    elif reason == 'inactive':
        message = 'Session timed out due to inactivity.'
    elif reason == 'unauthorized':
        message = 'Please login to access this page.'
    
    return render_template('login.html', message=message)

def create_new_session(username):
    """Create a new authenticated session"""
    # Generate unique session ID
    session_id = secrets.token_urlsafe(32)
    
    # Set session lifetime
    expiry_time = datetime.now() + app.config['PERMANENT_SESSION_LIFETIME']
    
    # Store session data
    sessions[session_id] = {
        'user_id': username,
        'created_at': datetime.now(),
        'last_activity': datetime.now(),
        'expiry': expiry_time,
        'ip_address': request.remote_addr,
        'user_agent': request.user_agent.string
    }
    
    # Set client-side session cookie
    session['session_id'] = session_id
    session['user_id'] = username
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    """Terminate session and logout user"""
    session_id = session.get('session_id')
    if session_id in sessions:
        sessions.pop(session_id)
    
    session.clear()
    return redirect(url_for('login', reason='logout'))

@app.route('/dashboard')
def dashboard():
    """Protected dashboard page"""
    session_id = session['session_id']
    session_data = sessions[session_id]
    
    return render_template('dashboard.html',
                           username=session['user_id'],
                           created=session_data['created_at'],
                           last_active=session_data['last_activity'])

@app.route('/session-info')
def session_info():
    """API endpoint for session information"""
    session_id = session.get('session_id')
    if not session_id or session_id not in sessions:
        return jsonify({'error': 'No active session'}), 401
    
    session_data = sessions[session_id]
    return jsonify({
        'user_id': session_data['user_id'],
        'created_at': session_data['created_at'].isoformat(),
        'last_activity': session_data['last_activity'].isoformat(),
        'expiry': session_data['expiry'].isoformat(),
        'ip_address': session_data['ip_address'],
        'user_agent': session_data['user_agent'],
        'timeout_seconds': app.config['SESSION_TIMEOUT']
    })

def authenticate_user(username, password):
    """Stub for authentication logic - replace with real implementation"""
    # In a real application, verify credentials against database
    return username == 'admin' and password == 'securepassword'

# Scheduled task to clean up expired sessions (run as cron job or background thread)
def clean_expired_sessions():
    current_time = datetime.now()
    expired_keys = [k for k, v in sessions.items() if v['expiry'] <= current_time]
    for key in expired_keys:
        sessions.pop(key, None)

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Remove adhoc SSL in production