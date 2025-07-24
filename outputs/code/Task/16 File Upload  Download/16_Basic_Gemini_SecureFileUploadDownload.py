import os
import magic
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    flash,
    render_template_string,
    send_from_directory,
    abort,
)
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

# --- Configuration ---
# It's recommended to store sensitive configuration in environment variables.
# For simplicity, we define them here.
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
SECRET_KEY = os.urandom(24)  # Generate a random secret key for session management

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["SECRET_KEY"] = SECRET_KEY


# --- HTML Template ---
# The entire frontend is embedded in this multi-line string.
HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure File Handler</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 20px auto; padding: 0 15px; }
        h1, h2 { color: #2c3e50; }
        .container { background: #f9f9f9; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .flashes { list-style: none; padding: 0; margin: 0 0 20px 0; }
        .flash-success { padding: 10px; border-radius: 4px; background: #2ecc71; color: white; }
        .flash-error { padding: 10px; border-radius: 4px; background: #e74c3c; color: white; }
        form { margin-bottom: 20px; }
        input[type="file"] { border: 1px solid #ccc; padding: 8px; border-radius: 4px; }
        input[type="submit"] { background: #3498db; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        input[type="submit"]:hover { background: #2980b9; }
        .file-list { list-style: none; padding: 0; }
        .file-list li { background: #ecf0f1; padding: 10px; border-radius: 4px; margin-bottom: 5px; display: flex; justify-content: space-between; align-items: center; }
        .file-list a { text-decoration: none; color: #3498db; font-weight: bold; }
        .file-list a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Secure File Handler</h1>

        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            <ul class=flashes>
            {% for category, message in messages %}
              <li class="flash-{{ category }}">{{ message }}</li>
            {% endfor %}
            </ul>
          {% endif %}
        {% endwith %}

        <section>
            <h2>Upload a New File</h2>
            <form method=post enctype=multipart/form-data>
              <input type=file name=file>
              <input type=submit value=Upload>
            </form>
            <p><small>Max file size: 16MB. Allowed types: txt, pdf, png, jpg, jpeg, gif.</small></p>
        </section>

        <hr>

        <section>
            <h2>Uploaded Files</h2>
            {% if files %}
                <ul class="file-list">
                {% for file in files %}
                    <li>
                        <span>{{ file }}</span>
                        <a href="{{ url_for('download_file', filename=file) }}">Download</a>
                    </li>
                {% endfor %}
                </ul>
            {% else %}
                <p>No files have been uploaded yet.</p>
            {% endif %}
        </section>
    </div>
</body>
</html>
"""


# --- Helper Functions ---
def allowed_file(filename):
    """Checks if the file's extension is in the allowed set."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def is_allowed_mimetype(file_stream):
    """
    Checks the file's MIME type against a whitelist by reading its magic numbers.
    Resets the file stream's position after reading.
    """
    allowed_mimetypes = [
        "image/jpeg", "image/png", "image/gif", "application/pdf", "text/plain"
    ]
    # Read the first 2048 bytes to determine the MIME type
    file_header = file_stream.read(2048)
    file_stream.seek(0)  # Reset stream position
    mime_type = magic.from_buffer(file_header, mime=True)
    return mime_type in allowed_mimetypes


# --- Routes ---
@app.route("/", methods=["GET", "POST"])
def index():
    """
    Main route that handles both file uploads and listing existing files.
    """
    if request.method == "POST":
        # --- File Upload Logic ---
        if "file" not in request.files:
            flash("No file part in the request.", "error")
            return redirect(request.url)

        file = request.files["file"]
        if file.filename == "":
            flash("No file selected.", "error")
            return redirect(request.url)

        # Securely validate the file before saving
        if file and allowed_file(file.filename) and is_allowed_mimetype(file.stream):
            filename = secure_filename(file.filename)
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            try:
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                flash(f'File "{filename}" has been uploaded successfully.', "success")
            except RequestEntityTooLarge:
                flash("File is larger than the 16MB limit.", "error")
                return redirect(request.url)
            return redirect(url_for("index"))
        else:
            flash("Invalid file type. Allowed types are: txt, pdf, png, jpg, jpeg, gif.", "error")
            return redirect(request.url)

    # --- File Listing Logic (for GET requests) ---
    uploaded_files = []
    upload_path = app.config["UPLOAD_FOLDER"]
    if os.path.exists(upload_path):
        # Sort files for consistent ordering
        uploaded_files = sorted(os.listdir(upload_path))

    return render_template_string(HTML_TEMPLATE, files=uploaded_files)


@app.route("/uploads/<path:filename>")
def download_file(filename):
    """
    Securely serves a file from the upload folder.
    - Uses send_from_directory to prevent path traversal attacks.
    - Includes a placeholder for an authorization check.
    """
    # **IMPORTANT**: In a real-world application, implement proper user
    # authentication and authorization here to ensure the user has the
    # right to download the requested file.
    # For example: if not current_user.is_authorized_for(filename): abort(403)

    try:
        return send_from_directory(
            app.config["UPLOAD_FOLDER"], filename, as_attachment=True
        )
    except FileNotFoundError:
        abort(404)


# --- Error Handling ---
@app.errorhandler(413)
def request_entity_too_large(error):
    """Custom error handler for files that are too large."""
    flash("File is larger than the 16MB limit.", "error")
    return redirect(request.url)


if __name__ == "__main__":
    app.run(debug=True)