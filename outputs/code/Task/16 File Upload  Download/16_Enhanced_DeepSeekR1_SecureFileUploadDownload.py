import os
import secrets
import string
from flask import Flask, request, send_from_directory, abort, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration - Set via environment variables in production
app.config.update(
    UPLOAD_FOLDER=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads'),
    ALLOWED_EXTENSIONS={'pdf', 'txt', 'png', 'jpg', 'jpeg', 'gif'},
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
    STORAGE_DIRECTORY='uploads',
    SERVE_UPLOADS_DIRECTLY=False  # Set to True only if serving static files
)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def generate_secure_filename(original_filename):
    """Generate a secure random filename with original extension"""
    ext = os.path.splitext(original_filename)[1]
    rand_str = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    return rand_str + ext.lower()

def is_allowed_file(filename):
    """Check if file has allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/upload', methods=['POST'])
def upload_file():
    """Secure file upload endpoint"""
    # Verify file exists in request
    if 'file' not in request.files:
        abort(400, 'No file part')
    
    file = request.files['file']
    
    # Verify filename exists
    if file.filename == '':
        abort(400, 'No selected file')
    
    # Validate file extension
    if not is_allowed_file(file.filename):
        abort(400, 'File type not allowed')
    
    # Secure filename handling
    original_filename = secure_filename(file.filename)
    server_filename = generate_secure_filename(original_filename)
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], server_filename)
    
    # Save file securely
    file.save(save_path)
    
    # Return server-generated filename
    return {'filename': server_filename}, 201

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    """Secure file download endpoint"""
    # Validate filename format
    if not all(c in string.ascii_letters + string.digits + '.' for c in filename):
        abort(400, 'Invalid filename')
    
    # Prevent path traversal
    if '..' in filename or filename.startswith('/'):
        abort(400, 'Invalid filename')
    
    # Verify file exists
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.isfile(file_path):
        abort(404, 'File not found')
    
    # Serve file securely
    if app.config['SERVE_UPLOADS_DIRECTLY']:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
    else:
        # More secure alternative: Redirect to separate storage service
        return redirect(f"https://storage.example.com/{filename}")

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Use real certificates in production