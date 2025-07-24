import os
import uuid
from flask import Flask, request, send_file, abort, make_response
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration (use environment variables in production)
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['SANITIZE_FILENAMES'] = True

# Create upload directory if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.chmod(app.config['UPLOAD_FOLDER'], 0o700)  # Restrict directory permissions

def allowed_file(filename):
    """Validate file extension and name"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return (
        ext in app.config['ALLOWED_EXTENSIONS'] and
        filename != '' and
        '\x00' not in filename
    )

def secure_download_path(filename):
    """Prevent path traversal attacks"""
    safe_dir = os.path.abspath(app.config['UPLOAD_FOLDER'])
    target_path = os.path.abspath(os.path.join(safe_dir, filename))
    return target_path if os.path.commonprefix([target_path, safe_dir]) == safe_dir else None

@app.route('/upload', methods=['POST'])
def upload_file():
    # Verify file exists in request
    if 'file' not in request.files:
        return {'error': 'No file part'}, 400
    
    file = request.files['file']
    
    # Check if file is selected
    if file.filename == '':
        return {'error': 'No selected file'}, 400
    
    # Validate file properties
    if not allowed_file(file.filename):
        return {'error': 'Invalid file type'}, 400
    
    # Generate secure filename
    original_ext = file.filename.rsplit('.', 1)[1].lower()
    if app.config['SANITIZE_FILENAMES']:
        base_name = secure_filename(file.filename.rsplit('.', 1)[0])
        safe_filename = f"{base_name}_{uuid.uuid4().hex}.{original_ext}"
    else:
        safe_filename = f"{uuid.uuid4().hex}.{original_ext}"
    
    # Save file securely
    dest_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    try:
        file.save(dest_path)
        os.chmod(dest_path, 0o600)  # Restrict file permissions
        return {'message': 'File uploaded', 'filename': safe_filename}, 201
    except Exception as e:
        app.logger.error(f"File save error: {str(e)}")
        return {'error': 'Server storage error'}, 500

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    # Validate download path
    file_path = secure_download_path(filename)
    if not file_path or not os.path.exists(file_path):
        abort(404)
    
    # Set security headers
    response = make_response(send_file(file_path, as_attachment=True))
    response.headers['Content-Security-Policy'] = "default-src 'none'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Use proper SSL cert in production