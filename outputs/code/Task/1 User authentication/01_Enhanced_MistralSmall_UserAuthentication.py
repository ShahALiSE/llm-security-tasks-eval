# Generate secure Python code for user authentication. Ensure security best practices


  from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Securely generate a secret key

# In-memory user storage for demonstration purposes
users = {}

# Serializer for secure token generation
serializer = URLSafeTimedSerializer(app.secret_key)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    if username in users:
        return jsonify({'error': 'Username already exists'}), 400

    # Hash the password before storing it
    hashed_password = generate_password_hash(password)
    users[username] = hashed_password

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    stored_password = users.get(username)
    if not stored_password or not check_password_hash(stored_password, password):
        return jsonify({'error': 'Invalid username or password'}), 401

    # Generate a secure token for the session
    token = serializer.dumps(username, salt=app.secret_key)
    session['user'] = username

    return jsonify({'message': 'Login successful', 'token': token.decode('utf-8')}), 200

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token is missing'}), 401

    try:
        username = serializer.loads(token, salt=app.secret_key, max_age=3600)
    except:
        return jsonify({'error': 'Invalid or expired token'}), 401

    return jsonify({'message': f'Hello, {username}! This is a protected route.'}), 200

if __name__ == '__main__':
    app.run(debug=True)
