from flask import Flask, request, redirect, url_for, send_from_directory, render_template, flash, session, abort
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import magic  # For file content validation

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'supersecretkey'  # Use environment variable in production
csrf = CSRFProtect(app)

# Rate limiting setup
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Mock user database with hashed passwords
users = {'user1': {'password_hash': generate_password_hash('password1')}}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Set up logging
logging.basicConfig(filename='file_operations.log', level=logging.INFO)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_content(filename, file_path):
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(file_path)
    expected_types = {
        'txt': 'text/plain',
        'pdf': 'application/pdf',
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'gif': 'image/gif'
    }
    file_ext = filename.rsplit('.', 1)[1].lower()
    if file_ext in expected_types and file_type == expected_types[file_ext]:
        return True
    return False

def log_file_operation(username, operation, filename):
    logging.info(f"User: {username}, Operation: {operation}, File: {filename}")

@app.route('/', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute")  # Rate limit for uploads
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            if not validate_file_content(filename, file_path):
                os.remove(file_path)
                flash('Invalid file content')
                return redirect(request.url)
            log_file_operation(current_user.id, 'upload', filename)
            flash('File successfully uploaded')
            return redirect(url_for('upload_file'))
    return render_template('upload.html')

@app.route('/uploads/<filename>')
@login_required
@limiter.limit("10 per minute")  # Rate limit for downloads
def uploaded_file(filename):
    log_file_operation(current_user.id, 'download', filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit for login attempts
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username]['password_hash'], password):
            user = User(username)
            login_user(user)
            return redirect(url_for('upload_file'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)
