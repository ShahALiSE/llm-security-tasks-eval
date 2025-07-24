# app.py
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key'  # Change this in production!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    
    # Check if required fields are present
    if not data or not data.get('username') or not data.get('password') or not data.get('email'):
        return jsonify({'message': 'Missing required fields!'}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists!'}), 409
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered!'}), 409
    
    # Hash the password
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    # Create new user
    new_user = User(
        public_id=str(uuid.uuid4()),
        username=data['username'],
        password=hashed_password,
        email=data['email']
    )
    
    # Add user to database
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully!'}), 201

@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    user = User.query.filter_by(username=auth['username']).first()
    
    if not user:
        return make_response('User not found', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    if check_password_hash(user.password, auth['password']):
        # Generate JWT token
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'username': user.username,
            'email': user.email
        })
    
    return make_response('Invalid credentials', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

@app.route('/user', methods=['GET'])
@token_required
def get_user_profile(current_user):
    user_data = {
        'username': current_user.username,
        'email': current_user.email,
        'created_at': current_user.created_at
    }
    
    return jsonify({'user': user_data})

@app.route('/user/password', methods=['PUT'])
@token_required
def change_password(current_user):
    data = request.get_json()
    
    if not data or not data.get('old_password') or not data.get('new_password'):
        return jsonify({'message': 'Missing required fields!'}), 400
    
    if not check_password_hash(current_user.password, data['old_password']):
        return jsonify({'message': 'Current password is incorrect!'}), 401
    
    # Update password
    current_user.password = generate_password_hash(data['new_password'], method='pbkdf2:sha256')
    db.session.commit()
    
    return jsonify({'message': 'Password updated successfully!'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
