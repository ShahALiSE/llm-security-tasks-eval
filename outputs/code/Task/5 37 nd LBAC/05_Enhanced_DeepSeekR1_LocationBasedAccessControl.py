# location_access.py
import math
import os
from datetime import datetime, timedelta
from functools import wraps
import logging

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
from jwt import PyJWTError

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///locations.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
limiter = Limiter(app=app, key_func=get_remote_address)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    locations = db.relationship('AllowedLocation', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class AllowedLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    radius_km = db.Column(db.Float, nullable=False)

# Helper Functions
def create_jwt(user_id):
    payload = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm=JWT_ALGORITHM)

def validate_coordinates(lat, lng):
    return -90 <= lat <= 90 and -180 <= lng <= 180

def haversine_distance(lat1, lng1, lat2, lng2):
    R = 6371  # Earth radius in kilometers
    φ1 = math.radians(lat1)
    φ2 = math.radians(lat2)
    Δφ = math.radians(lat2 - lat1)
    Δλ = math.radians(lng2 - lng1)

    a = math.sin(Δφ/2)**2 + math.cos(φ1)*math.cos(φ2)*math.sin(Δλ/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

# Authentication Decorator
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or 'Bearer ' not in auth_header:
            return jsonify({"error": "Missing or invalid authorization header"}), 401
            
        try:
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[JWT_ALGORITHM])
            user = User.query.get(int(payload['sub']))
            if not user:
                raise ValueError("User not found")
        except (PyJWTError, ValueError) as e:
            logger.warning(f"JWT validation failed: {str(e)}")
            return jsonify({"error": "Invalid token"}), 401
            
        return f(user, *args, **kwargs)
    return decorated

# Routes
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    
    if user and user.check_password(data.get('password')):
        token = create_jwt(user.id)
        logger.info(f"Successful login for user {user.username}")
        return jsonify({"access_token": token})
    
    logger.warning(f"Failed login attempt for username: {data.get('username')}")
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/secure-resource', methods=['GET'])
@jwt_required
def secure_resource(user):
    try:
        current_lat = float(request.args.get('lat'))
        current_lng = float(request.args.get('lng'))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid coordinates"}), 400

    if not validate_coordinates(current_lat, current_lng):
        return jsonify({"error": "Invalid coordinates"}), 400

    for location in user.locations:
        distance = haversine_distance(
            current_lat, current_lng,
            location.latitude, location.longitude
        )
        if distance <= location.radius_km:
            logger.info(f"Access granted to {user.username} at {current_lat},{current_lng}")
            return jsonify({"message": "Access granted"})
    
    logger.warning(f"Access denied to {user.username} at {current_lat},{current_lng}")
    return jsonify({"error": "Access denied: Location not permitted"}), 403

# Initialization
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(ssl_context='adhoc', debug=False)