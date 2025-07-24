from flask import Flask, request, send_from_directory, redirect, url_for, render_template_string, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import Form, StringField, PasswordField, validators
import os

app = Flask(__name__)
csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configuration
app.config['UPLOAD_FOLDER'] = '/path/to/uploads'  # Change this to your desired upload folder
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this in production
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Mock database for users
users = {
    "username": {
        "password_hash": generate_password_hash("password"),
        "id": 1
    }
}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    # Look up user in database (here we use the mock users dict)
    for username, user_data in users.items():
        if user_data['id'] == int(user_id):
            return User(user_data['id'])
    return None

# Forms
class LoginForm(Form):
    username = StringField('Username', [validators.InputRequired()])
    password = PasswordField('Password', [validators.InputRequired()])

class UploadForm(Form):
    file = FileField('File', validators=[FileRequired(), FileAllowed(app.config['ALLOWED_EXTENSIONS'])])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def safe_join(base, path):
    """Safely join paths to avoid directory traversal."""
    full_path = os.path.join(base, path)
    if not os.path.abspath(full_path).startswith(os.path.abspath(base)):
        raise ValueError("Invalid path")
    return full_path

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data
        if username in users and check_password_hash(users[username]['password_hash'], password):
            user = User(users[username]['id'])
            login_user(user)
            return redirect(url_for('upload_file'))
        flash('Invalid username or password')
    return render_template_string('''
    <!doctype html>
    <title>Login</title>
    <h1>Login</h1>
    <form method=post>
      <label>Username:</label>
      <input type=text name=username required>
      <label>Password:</label>
      <input type=password name=password required>
      {{ form.csrf_token }}
      <input type=submit value=Login>
    </form>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul>
        {% for message in messages %}
          <li>{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
    ''', form=form)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = UploadForm.from_flask(request)
    if request.method == 'POST' and form.validate():
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash('File uploaded successfully')
        return redirect(url_for('upload_file'))
    return render_template_string('''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul>
        {% for message in messages %}
          <li>{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
      {{ form.csrf_token }}
    </form>
    <a href="{{ url_for('logout') }}">Logout</a>
    ''', form=form)

@app.route('/download/<name>')
@login_required
def download_file(name):
    try:
        file_path = safe_join(app.config['UPLOAD_FOLDER'], name)
        if os.path.exists(file_path):
            return send_from_directory(app.config['UPLOAD_FOLDER'], name, as_attachment=True)
        else:
            flash('File not found')
            return redirect(url_for('upload_file'))
    except ValueError:
        flash('Invalid file path')
        return redirect(url_for('upload_file'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    # For local testing with HTTPS
    # In production, use a proper WSGI server like Gunicorn with Nginx and proper SSL certificates
    app.run(ssl_context='adhoc')
