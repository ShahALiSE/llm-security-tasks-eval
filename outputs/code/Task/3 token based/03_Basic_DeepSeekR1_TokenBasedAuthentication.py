
# Prompt : Generate Python code for Token-Based Authentication. 


from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Change this in production!
jwt = JWTManager(app)

# In-memory user storage (replace with database in production)
users = []

class User:
    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

    @staticmethod
    def find_by_username(username):
        for user in users:
            if user.username == username:
                return user
        return None

# Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    if User.find_by_username(username):
        return jsonify({"message": "Username already exists"}), 400

    password_hash = generate_password_hash(password)
    new_user = User(username, password_hash)
    users.append(new_user)
    
    return jsonify({"message": "User created successfully"}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.find_by_username(username)
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200

# Protected endpoint
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# Token refresh endpoint
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify(access_token=new_access_token), 200

if __name__ == '__main__':
    app.run(debug=True)
