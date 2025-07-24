# Generate secure Python code for Token-Based Authentication. Ensure security best practices.

from flask import Flask, request, jsonify
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Use a strong, random secret key

# In-memory user store for demonstration purposes
users = {
    "user1": generate_password_hash("password1"),
    "user2": generate_password_hash("password2")
}

def create_token(username):
    token = jwt.encode({
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expiration time
    }, app.config['SECRET_KEY'], algorithm='HS256')
    return token

def verify_token(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return data
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users and check_password_hash(users[username], password):
        token = create_token(username)
        return jsonify({'token': token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if token and verify_token(token):
        return jsonify({'message': 'Access granted'}), 200
    return jsonify({'message': 'Access denied'}), 403

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Use HTTPS in production with a proper SSL certificate
