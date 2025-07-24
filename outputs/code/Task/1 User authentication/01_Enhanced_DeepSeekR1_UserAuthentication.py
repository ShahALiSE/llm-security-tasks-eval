import re
from datetime import datetime, timedelta
import jwt
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Use environment variable in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['BCRYPT_LOG_ROUNDS'] = 12

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Helper Functions
def is_valid_email(email):
    """Validate email format using regex"""
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None

def is_strong_password(password):
    """Validate password strength"""
    if len(password) < 10:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def create_jwt_token(user_id):
    """Create JWT token with expiration"""
    payload = {
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow(),
        'sub': user_id
    }
    return jwt.encode(
        payload,
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    if not is_valid_email(email):
        return jsonify({'error': 'Invalid email format'}), 400

    if not is_strong_password(password):
        return jsonify({'error': 'Password must be at least 10 characters with uppercase, lowercase, number, and special character'}), 400

    try:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Email already registered'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    try:
        auth_token = create_jwt_token(user.id)
        response = make_response(jsonify({'message': 'Login successful'}))
        response.set_cookie(
            'auth_token',
            auth_token,
            httponly=True,
            secure=True,  # In production, set this to True
            samesite='Strict',
            max_age=3600
        )
        return response
    except Exception as e:
        return jsonify({'error': 'Could not create token'}), 500

@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(jsonify({'message': 'Logged out successfully'}))
    response.delete_cookie('auth_token')
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(ssl_context='adhoc')  # Use proper SSL certificate in production