# Generate secure Python code for Token-Based Authentication. Ensure security best practices.

import os
import datetime
import bcrypt
import jwt
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-strong-secret-key-here')

# In-memory "database" for demonstration purposes only
users = []

class User:
    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

def generate_token(username):
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
            'iat': datetime.datetime.utcnow(),
            'sub': username
        }
        return jwt.encode(
            payload,
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
    except Exception as e:
        return e

def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Token expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'

def token_required(f):
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Bearer token malformed.'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing.'}), 401

        username = verify_token(token)
        if isinstance(username, str):
            return f(username, *args, **kwargs)
        return jsonify({'message': username}), 401
    return decorator

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400

    if any(u.username == username for u in users):
        return jsonify({'message': 'Username already exists'}), 409

    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    users.append(User(username, password_hash))
    
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Username and password required'}), 400

    user = next((u for u in users if u.username == auth['username']), None)
    
    if not user or not bcrypt.checkpw(auth['password'].encode('utf-8'), user.password_hash):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = generate_token(user.username)
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    
    return jsonify({'token': token}), 200

@app.route('/protected', methods=['GET'])
@token_required
def protected(username):
    return jsonify({'message': f'Hello, {username}! This is a protected route.'}), 200

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Remove in production when behind HTTPS proxy