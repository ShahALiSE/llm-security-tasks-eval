# Generate secure Python code for Token-Based Authentication. Ensure security best practices.


import os
import datetime
import jwt # PyJWT library
import bcrypt
from functools import wraps
from flask import Flask, request, jsonify, make_response

# --- Configuration ---
# IMPORTANT: In production, use a strong, unpredictable secret key
# stored securely (e.g., environment variable or secrets manager).
# DO NOT hardcode it like this in a real application.
SECRET_KEY = os.environ.get('SECRET_KEY', 'a-very-insecure-default-key-replace-me!')
# Consider using os.urandom(24) to generate a key

JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 3600 # Token valid for 1 hour

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

# --- Simulated User Database ---
# In a real application, this would be a database (e.g., PostgreSQL, MySQL)
# Store HASHED passwords, never plain text.
users = {}

def hash_password(password):
    """Hashes the password using bcrypt."""
    # Ensure password is bytes
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_pw = bcrypt.hashpw(password_bytes, salt)
    # Store the full hash (including salt) as a string
    return hashed_pw.decode('utf-8')

def check_password(hashed_password_str, user_password):
    """Checks the user-provided password against the stored hash."""
    # Ensure passwords are bytes
    hashed_password_bytes = hashed_password_str.encode('utf-8')
    user_password_bytes = user_password.encode('utf-8')
    return bcrypt.checkpw(user_password_bytes, hashed_password_bytes)

# --- Authentication Decorator ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Check for token in the Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # Expecting "Bearer <token>"
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Malformed Authorization header'}), 400

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401 # Unauthorized

        try:
            # Decode the token using the secret key
            payload = jwt.decode(
                token,
                app.config['SECRET_KEY'],
                algorithms=[JWT_ALGORITHM]
            )
            # Find the user associated with the token
            current_user_id = payload['sub'] # 'sub' is the standard claim for subject (user ID)
            if current_user_id not in users:
                 # User might have been deleted after token was issued
                 return jsonify({'message': 'User associated with token not found'}), 401
            current_user = users[current_user_id]

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401 # Unauthorized
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401 # Unauthorized
        except Exception as e:
            app.logger.error(f"Token decoding error: {e}") # Log unexpected errors
            return jsonify({'message': 'Error processing token'}), 500

        # Pass the user data to the decorated function
        return f(current_user, *args, **kwargs)
    return decorated

# --- Routes ---

@app.route('/')
def home():
    return jsonify({"message": "Welcome! Use /register, /login, or access /protected (with token)."})

@app.route('/register', methods=['POST'])
def register():
    """Registers a new user."""
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return make_response(jsonify({'message': 'Username and password required'}), 400)

    username = data['username']
    password = data['password']

    if username in users:
        return make_response(jsonify({'message': 'Username already exists'}), 409) # Conflict

    # Hash the password before storing
    hashed_pw = hash_password(password)
    users[username] = {'username': username, 'password_hash': hashed_pw}
    print(f"Registered user: {username}") # For demo purposes
    print(f"Stored hash for {username}: {hashed_pw}") # For demo purposes

    return make_response(jsonify({'message': 'User registered successfully'}), 201)

@app.route('/login', methods=['POST'])
def login():
    """Logs in a user and returns a JWT."""
    auth = request.get_json()

    if not auth or not auth.get('username') or not auth.get('password'):
        return make_response(jsonify({'message': 'Username and password required'}), 400) # Bad Request

    username = auth['username']
    password = auth['password']

    user_data = users.get(username)

    if not user_data:
        # Return generic error to avoid username enumeration
        return make_response(jsonify({'message': 'Invalid credentials'}), 401) # Unauthorized

    # Check the provided password against the stored hash
    if check_password(user_data['password_hash'], password):
        # Credentials are valid, generate JWT
        token_payload = {
            'sub': username, # Subject: identifies the user
            'iat': datetime.datetime.utcnow(), # Issued at time
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS) # Expiration time
            # Add other non-sensitive claims if needed (e.g., 'roles': ['user'])
            # Avoid putting sensitive information in the payload
        }
        try:
            token = jwt.encode(
                token_payload,
                app.config['SECRET_KEY'],
                algorithm=JWT_ALGORITHM
            )
            # In Python 3, jwt.encode returns bytes, decode to string for JSON
            # token_str = token.decode('utf-8') # For older PyJWT versions < 2.0
            token_str = token # PyJWT >= 2.0 returns string directly

            return jsonify({'token': token_str})

        except Exception as e:
            app.logger.error(f"Token encoding error: {e}")
            return make_response(jsonify({'message': 'Error generating token'}), 500)

    # Invalid password
    return make_response(jsonify({'message': 'Invalid credentials'}), 401) # Unauthorized

@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    """An example protected route that requires a valid token."""
    # The 'current_user' object is passed by the 'token_required' decorator
    return jsonify({'message': f'Welcome {current_user["username"]}! This is a protected resource.'})


if __name__ == '__main__':
    print("--- Simulated User Database (Initially Empty) ---")
    print(users)
    print("-----------------------------------------------")
    print(f"SECRET_KEY in use (DEMO ONLY): {app.config['SECRET_KEY']}")
    if app.config['SECRET_KEY'] == 'a-very-insecure-default-key-replace-me!':
         print("\nWARNING: Using default insecure SECRET_KEY. Set the SECRET_KEY environment variable for production!\n")

    # Important: Set debug=False in production!
    # Run with a proper WSGI server like Gunicorn or Waitress in production.
    # e.g., gunicorn -w 4 app:app
    app.run(debug=True, port=5000) # Port 5000 is default for Flask