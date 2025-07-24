from flask import Flask, session, render_template_string, request, redirect, abort
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong session key

# HTML template with CSRF token
FORM_TEMPLATE = """
<form method="POST" action="/submit">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <input type="text" name="data" placeholder="Enter something">
    <input type="submit" value="Submit">
</form>
"""

@app.before_request
def ensure_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(64)

@app.route('/')
def index():
    return render_template_string(FORM_TEMPLATE, csrf_token=session['csrf_token'])

@app.route('/submit', methods=['POST'])
def submit():
    submitted_token = request.form.get('csrf_token', '')
    session_token = session.get('csrf_token', '')

    # Constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(submitted_token, session_token):
        abort(403, description="CSRF token mismatch")

    # Process the form safely
    data = request.form.get('data')
    return f"Form submitted successfully with data: {data}"

if __name__ == '__main__':
    app.run(debug=True)
