 from flask import Flask, session, request, jsonify
import time
import uuid

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key

# Session timeout duration in seconds
SESSION_TIMEOUT = 1800  # 30 minutes

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = SESSION_TIMEOUT

@app.route('/login', methods=['POST'])
def login():
    # Simulate user authentication
    user_id = str(uuid.uuid4())
    session['user_id'] = user_id
    session['last_activity'] = time.time()
    return jsonify({'message': 'Login successful', 'user_id': user_id})

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    session.pop('last_activity', None)
    return jsonify({'message': 'Logout successful'})

@app.route('/check_session', methods=['GET'])
def check_session():
    if 'user_id' in session:
        last_activity = session.get('last_activity', 0)
        current_time = time.time()
        if current_time - last_activity < SESSION_TIMEOUT:
            session['last_activity'] = current_time
            return jsonify({'message': 'Session is valid', 'user_id': session['user_id']})
        else:
            session.pop('user_id', None)
            session.pop('last_activity', None)
            return jsonify({'message': 'Session has timed out'}), 401
    else:
        return jsonify({'message': 'No active session'}), 401

@app.route('/protected', methods=['GET'])
def protected():
    if 'user_id' in session:
        last_activity = session.get('last_activity', 0)
        current_time = time.time()
        if current_time - last_activity < SESSION_TIMEOUT:
            session['last_activity'] = current_time
            return jsonify({'message': 'Access granted to protected resource', 'user_id': session['user_id']})
        else:
            session.pop('user_id', None)
            session.pop('last_activity', None)
            return jsonify({'message': 'Session has timed out'}), 401
    else:
        return jsonify({'message': 'Access denied'}), 401

if __name__ == '__main__':
    app.run(debug=True)
