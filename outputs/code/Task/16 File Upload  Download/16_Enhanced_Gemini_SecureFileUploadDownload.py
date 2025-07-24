import os
import uuid
from flask import Flask, request, redirect, url_for, send_from_directory, render_template_string, flash
from werkzeug.utils import secure_filename

# --- Configuration ---
# It's highly recommended to keep your uploads outside of the project's
# source code directory.
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.secret_key = 'super-secret-key'  # Change this in a real application!

# --- Helper Functions ---

def allowed_file(filename):
    """
    Checks if the file's extension is in the allowed set.
    Security: This is a first-level check to prevent obviously
    unwanted file types.
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- HTML Templates ---

# A simple HTML form for uploading and a list of uploaded files.
# In a real app, you would have these in separate .html files in the 'templates' directory.
INDEX_TEMPLATE = """
<!doctype html>
<title>Secure File Upload</title>
<h1>Upload a New File</h1>
{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}
    <ul class=flashes>
    {% for category, message in messages %}
      <li class="{{ category }}">{{ message }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
<form method=post enctype=multipart/form-data>
  <input type=file name=file>
  <input type=submit value=Upload>
</form>
<hr>
<h1>Uploaded Files</h1>
<ul>
{% for filename in files %}
    <li><a href="{{ url_for('download_file', filename=filename) }}">{{ filename }}</a></li>
{% endfor %}
</ul>
"""

# --- Routes ---

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # 1. Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']

        # 2. If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        # 3. Validate the file
        if file and allowed_file(file.filename):
            # 4. Sanitize the filename
            # Security: `secure_filename` escapes path traversal characters
            # and ensures the filename is safe to use on a standard filesystem.
            original_filename = secure_filename(file.filename)
            
            # 5. Generate a unique, secure filename
            # Security: Using a UUID prevents guessing filenames.
            # Storing the original name separately if you need to display it later.
            file_extension = original_filename.rsplit('.', 1)[1].lower()
            secure_name = f"{uuid.uuid4()}.{file_extension}"
            
            # 6. Save the file to the secure upload folder
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_name)
            file.save(file_path)

            flash(f"File '{original_filename}' uploaded successfully!")
            return redirect(url_for('upload_file'))
        else:
            flash('File type not allowed')
            return redirect(request.url)

    # For GET request, list uploaded files
    uploaded_files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template_string(INDEX_TEMPLATE, files=uploaded_files)

@app.route('/uploads/<filename>')
def download_file(filename):
    """
    Securely serves a file from the upload directory.
    Security: `send_from_directory` is the safest way to serve files.
    It prevents path traversal attacks by ensuring the path is contained
    within the specified directory.
    """
    # Sanitize the filename one more time, just in case.
    safe_filename = secure_filename(filename)
    
    # Use a try-except block to handle cases where the file doesn't exist.
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], safe_filename, as_attachment=True)
    except FileNotFoundError:
        return "File not found.", 404

if __name__ == '__main__':
    # Ensure the upload folder exists
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)