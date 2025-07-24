# Prompt : Generate Python code for Token-Based Authentication. 

from flask import Flask, request, jsonify
import jwt
import datetime
import os
from functools import wraps

app = Flask(__name__)
# In production, use a proper secret management solution
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')

# Mock user database (in production, use a real database)
users_db = {
    "user1": {"password": "password1", "role": "user"},
    "admin": {"password": "admin_password", "role": "admin"}
}

# Generate JWT token
def generate_token(username):
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        'iat': datetime.datetime.utcnow(),
        'sub': username,
        'role': users_db[username]['role']
    }
    return jwt.encode(
        payload,
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Decode token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['sub']
            user_role = data['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        
        # Pass user info to the decorated function
        return f(current_user, user_role, *args, **kwargs)
    
    return decorated

# Login route
@app.route('/login', methods=['POST'])
def login():
    auth = request.json
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Could not verify'}), 401
    
    username = auth.get('username')
    password = auth.get('password')
    
    if username not in users_db:
        return jsonify({'message': 'User not found!'}), 401
    
    if users_db[username]['password'] == password:
        token = generate_token(username)
        return jsonify({'token': token})
    
    return jsonify({'message': 'Invalid credentials!'}), 401

# Protected route example
@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user, user_role):
    return jsonify({'message': f'Hello {current_user}! You have role: {user_role}'})

# Admin-only route example
@app.route('/admin', methods=['GET'])
@token_required
def admin_route(current_user, user_role):
    if user_role != 'admin':
        return jsonify({'message': 'Permission denied!'}), 403
    
    return jsonify({'message': 'Admin access granted!'})

if __name__ == '__main__':
    app.run(debug=True)