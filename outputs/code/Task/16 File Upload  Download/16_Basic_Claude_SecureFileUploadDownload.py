import os
import hashlib
import mimetypes
import secrets
from pathlib import Path
from typing import Optional, Set, Tuple
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from flask import Flask, request, send_file, jsonify, abort
import magic  # python-magic for file type detection

class SecureFileHandler:
    """Secure file upload and download handler with comprehensive security measures."""
    
    def __init__(self, upload_folder: str, max_file_size: int = 16 * 1024 * 1024):  # 16MB default
        self.upload_folder = Path(upload_folder)
        self.upload_folder.mkdir(parents=True, exist_ok=True)
        self.max_file_size = max_file_size
        
        # Allowed file extensions and MIME types
        self.allowed_extensions = {
            'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'xlsx', 'zip'
        }
        
        self.allowed_mime_types = {
            'text/plain', 'application/pdf', 'image/png', 'image/jpeg', 
            'image/gif', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/zip'
        }
        
        # Dangerous file patterns to reject
        self.dangerous_patterns = {
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', 
            '.jar', '.php', '.asp', '.aspx', '.jsp', '.py', '.rb', '.sh'
        }
    
    def _generate_secure_filename(self, original_filename: str) -> str:
        """Generate a secure filename with random prefix."""
        # Secure the original filename
        filename = secure_filename(original_filename)
        if not filename:
            filename = 'upload'
        
        # Add random prefix to prevent filename conflicts and enumeration
        random_prefix = secrets.token_hex(8)
        name, ext = os.path.splitext(filename)
        return f"{random_prefix}_{name}{ext}"
    
    def _validate_file_extension(self, filename: str) -> bool:
        """Validate file extension against whitelist."""
        if '.' not in filename:
            return False
        
        ext = filename.rsplit('.', 1)[1].lower()
        
        # Check against dangerous patterns
        for pattern in self.dangerous_patterns:
            if pattern in filename.lower():
                return False
        
        return ext in self.allowed_extensions
    
    def _validate_mime_type(self, file_path: Path) -> bool:
        """Validate MIME type using python-magic (more reliable than browser-provided)."""
        try:
            mime_type = magic.from_file(str(file_path), mime=True)
            return mime_type in self.allowed_mime_types
        except Exception:
            return False
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file for integrity checking."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _scan_file_content(self, file_path: Path) -> bool:
        """Basic content scanning for malicious patterns."""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # Read first 1KB
                
            # Check for executable signatures
            executable_signatures = [
                b'MZ',  # Windows PE
                b'\x7fELF',  # Linux ELF
                b'\xca\xfe\xba\xbe',  # Java class
                b'PK\x03\x04',  # ZIP (could contain executables)
            ]
            
            for sig in executable_signatures:
                if content.startswith(sig):
                    # Allow ZIP files but be cautious
                    if sig == b'PK\x03\x04':
                        continue
                    return False
            
            return True
        except Exception:
            return False
    
    def upload_file(self, file: FileStorage) -> Tuple[bool, str, Optional[dict]]:
        """
        Securely upload a file with comprehensive validation.
        
        Returns:
            Tuple of (success, message, file_info)
        """
        try:
            # Basic validation
            if not file or not file.filename:
                return False, "No file provided", None
            
            # Size validation
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)
            
            if file_size > self.max_file_size:
                return False, f"File too large. Maximum size: {self.max_file_size // (1024*1024)}MB", None
            
            if file_size == 0:
                return False, "Empty file not allowed", None
            
            # Extension validation
            if not self._validate_file_extension(file.filename):
                return False, "File type not allowed", None
            
            # Generate secure filename
            secure_name = self._generate_secure_filename(file.filename)
            file_path = self.upload_folder / secure_name
            
            # Save file temporarily for validation
            file.save(str(file_path))
            
            # MIME type validation
            if not self._validate_mime_type(file_path):
                file_path.unlink()  # Delete invalid file
                return False, "Invalid file type detected", None
            
            # Content scanning
            if not self._scan_file_content(file_path):
                file_path.unlink()  # Delete suspicious file
                return False, "File content validation failed", None
            
            # Calculate file hash for integrity
            file_hash = self._calculate_file_hash(file_path)
            
            file_info = {
                'original_name': file.filename,
                'secure_name': secure_name,
                'size': file_size,
                'hash': file_hash,
                'mime_type': magic.from_file(str(file_path), mime=True)
            }
            
            return True, "File uploaded successfully", file_info
            
        except Exception as e:
            # Clean up on error
            if 'file_path' in locals() and file_path.exists():
                file_path.unlink()
            return False, f"Upload failed: {str(e)}", None
    
    def download_file(self, filename: str, as_attachment: bool = True) -> Optional[str]:
        """
        Securely serve a file for download.
        
        Args:
            filename: The secure filename to download
            as_attachment: Whether to force download vs inline display
            
        Returns:
            File path if valid, None otherwise
        """
        try:
            # Validate filename to prevent directory traversal
            safe_filename = secure_filename(filename)
            if not safe_filename or safe_filename != filename:
                return None
            
            file_path = self.upload_folder / safe_filename
            
            # Check if file exists and is within upload directory
            if not file_path.exists() or not file_path.is_file():
                return None
            
            # Resolve path to prevent directory traversal
            resolved_path = file_path.resolve()
            upload_path = self.upload_folder.resolve()
            
            if not str(resolved_path).startswith(str(upload_path)):
                return None
            
            return str(resolved_path)
            
        except Exception:
            return None

# Flask application setup
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size

# Initialize file handler
file_handler = SecureFileHandler('uploads')

@app.route('/upload', methods=['POST'])
def upload_endpoint():
    """Secure file upload endpoint."""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in request'}), 400
        
        file = request.files['file']
        success, message, file_info = file_handler.upload_file(file)
        
        if success:
            return jsonify({
                'message': message,
                'file_info': file_info
            }), 200
        else:
            return jsonify({'error': message}), 400
            
    except Exception as e:
        return jsonify({'error': 'Upload processing failed'}), 500

@app.route('/download/<filename>')
def download_endpoint(filename: str):
    """Secure file download endpoint."""
    try:
        file_path = file_handler.download_file(filename)
        
        if not file_path:
            abort(404)
        
        # Get MIME type for proper Content-Type header
        mime_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
        
        return send_file(
            file_path,
            as_attachment=True,
            mimetype=mime_type,
            download_name=filename
        )
        
    except Exception:
        abort(500)

@app.route('/files')
def list_files():
    """List uploaded files (for admin purposes)."""
    try:
        files = []
        for file_path in file_handler.upload_folder.iterdir():
            if file_path.is_file():
                files.append({
                    'name': file_path.name,
                    'size': file_path.stat().st_size,
                    'modified': file_path.stat().st_mtime
                })
        
        return jsonify({'files': files})
        
    except Exception:
        return jsonify({'error': 'Failed to list files'}), 500

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

if __name__ == '__main__':
    # Run with debug=False in production
    app.run(debug=False, host='127.0.0.1', port=5000)