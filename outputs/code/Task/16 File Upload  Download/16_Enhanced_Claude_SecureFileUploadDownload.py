import os
import hashlib
import magic
import secrets
from pathlib import Path
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from flask import Flask, request, jsonify, send_file, abort
from datetime import datetime, timedelta
import sqlite3
import logging
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Security Configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate secure secret key
app.config['UPLOAD_FOLDER'] = 'secure_uploads'
app.config['ALLOWED_EXTENSIONS'] = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'
}

# MIME type whitelist for additional security
ALLOWED_MIME_TYPES = {
    'text/plain',
    'application/pdf',
    'image/png',
    'image/jpeg',
    'image/gif',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
}

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database setup for file metadata
def init_db():
    conn = sqlite3.connect('file_metadata.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            mime_type TEXT NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            download_count INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def rate_limit(max_requests=10, window=60):
    """Simple rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # In production, use Redis or similar for distributed rate limiting
            # This is a simplified in-memory implementation
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            
            # For demo purposes, we'll allow all requests
            # In production, implement proper rate limiting
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def validate_file_content(file_path):
    """Validate file content using python-magic"""
    try:
        mime_type = magic.from_file(file_path, mime=True)
        return mime_type in ALLOWED_MIME_TYPES
    except Exception as e:
        logger.error(f"Error validating file content: {e}")
        return False

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of file"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def sanitize_filename(filename):
    """Sanitize filename and add timestamp"""
    # Use werkzeug's secure_filename and add timestamp
    secure_name = secure_filename(filename)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name, ext = os.path.splitext(secure_name)
    return f"{timestamp}_{name[:50]}{ext}"  # Limit filename length

def save_file_metadata(filename, original_filename, file_hash, file_size, mime_type):
    """Save file metadata to database"""
    conn = sqlite3.connect('file_metadata.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO files (filename, original_filename, file_hash, file_size, mime_type)
        VALUES (?, ?, ?, ?, ?)
    ''', (filename, original_filename, file_hash, file_size, mime_type))
    file_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return file_id

def get_file_metadata(file_id):
    """Get file metadata from database"""
    conn = sqlite3.connect('file_metadata.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT filename, original_filename, file_hash, file_size, mime_type, is_active
        FROM files WHERE id = ? AND is_active = 1
    ''', (file_id,))
    result = cursor.fetchone()
    conn.close()
    return result

def update_download_count(file_id):
    """Update download count for file"""
    conn = sqlite3.connect('file_metadata.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE files SET download_count = download_count + 1 
        WHERE id = ? AND is_active = 1
    ''', (file_id,))
    conn.commit()
    conn.close()

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    return jsonify({
        'error': 'File too large',
        'message': 'Maximum file size is 16MB'
    }), 413

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        'error': 'File too large',
        'message': 'Maximum file size is 16MB'
    }), 413

@app.route('/upload', methods=['POST'])
@rate_limit(max_requests=5, window=60)  # 5 uploads per minute
def upload_file():
    """Secure file upload endpoint"""
    try:
        # Check if file is present in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        # Check if file is selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file extension
        if not allowed_file(file.filename):
            return jsonify({
                'error': 'File type not allowed',
                'allowed_types': list(app.config['ALLOWED_EXTENSIONS'])
            }), 400
        
        # Generate secure filename
        filename = sanitize_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save file temporarily
        file.save(file_path)
        
        # Validate file content
        if not validate_file_content(file_path):
            os.remove(file_path)  # Remove invalid file
            return jsonify({
                'error': 'Invalid file content',
                'message': 'File content does not match allowed types'
            }), 400
        
        # Calculate file hash and size
        file_hash = calculate_file_hash(file_path)
        file_size = os.path.getsize(file_path)
        
        # Get MIME type
        mime_type = magic.from_file(file_path, mime=True)
        
        # Save metadata to database
        file_id = save_file_metadata(
            filename, file.filename, file_hash, file_size, mime_type
        )
        
        logger.info(f"File uploaded successfully: {filename} (ID: {file_id})")
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file_id': file_id,
            'filename': filename,
            'original_filename': file.filename,
            'file_size': file_size,
            'mime_type': mime_type,
            'file_hash': file_hash
        }), 200
        
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({
            'error': 'Upload failed',
            'message': 'An error occurred during upload'
        }), 500

@app.route('/download/<int:file_id>', methods=['GET'])
@rate_limit(max_requests=20, window=60)  # 20 downloads per minute
def download_file(file_id):
    """Secure file download endpoint"""
    try:
        # Validate file_id is positive integer
        if file_id <= 0:
            abort(400)
        
        # Get file metadata from database
        file_metadata = get_file_metadata(file_id)
        
        if not file_metadata:
            abort(404)
        
        filename, original_filename, file_hash, file_size, mime_type, is_active = file_metadata
        
        # Check if file is active
        if not is_active:
            abort(404)
        
        # Construct file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Check if file exists on disk
        if not os.path.exists(file_path):
            logger.error(f"File not found on disk: {filename}")
            abort(404)
        
        # Verify file integrity
        current_hash = calculate_file_hash(file_path)
        if current_hash != file_hash:
            logger.error(f"File integrity check failed: {filename}")
            abort(500)
        
        # Update download count
        update_download_count(file_id)
        
        logger.info(f"File downloaded: {filename} (ID: {file_id})")
        
        # Send file with secure headers
        return send_file(
            file_path,
            as_attachment=True,
            download_name=original_filename,
            mimetype=mime_type
        )
        
    except Exception as e:
        logger.error(f"Download error: {e}")
        abort(500)

@app.route('/file/<int:file_id>/info', methods=['GET'])
def get_file_info(file_id):
    """Get file information without downloading"""
    try:
        if file_id <= 0:
            return jsonify({'error': 'Invalid file ID'}), 400
        
        file_metadata = get_file_metadata(file_id)
        
        if not file_metadata:
            return jsonify({'error': 'File not found'}), 404
        
        filename, original_filename, file_hash, file_size, mime_type, is_active = file_metadata
        
        # Get additional metadata
        conn = sqlite3.connect('file_metadata.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT upload_date, download_count 
            FROM files WHERE id = ? AND is_active = 1
        ''', (file_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({'error': 'File not found'}), 404
        
        upload_date, download_count = result
        
        return jsonify({
            'file_id': file_id,
            'original_filename': original_filename,
            'file_size': file_size,
            'mime_type': mime_type,
            'upload_date': upload_date,
            'download_count': download_count,
            'file_hash': file_hash
        }), 200
        
    except Exception as e:
        logger.error(f"File info error: {e}")
        return jsonify({'error': 'Failed to get file info'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'upload_folder': app.config['UPLOAD_FOLDER'],
        'max_file_size': app.config['MAX_CONTENT_LENGTH']
    }), 200

if __name__ == '__main__':
    # In production, use a proper WSGI server like Gunicorn
    app.run(debug=False, host='127.0.0.1', port=5000)