from flask import Flask, render_template_string, request, session, redirect, url_for, abort
import secrets

app = Flask(__name__)
app.secret_key = 'replace_with_your_secret_key'  # Needed for sessions

# HTML template with CSRF token
form_template = """
<!doctype html>
<title>CSRF Protected Form</title>
<h1>Submit Form</h1>
<form method="post" action="/submit">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <input type="text" name="data" placeholder="Enter some data">
    <input type="submit" value="Submit">
</form>
"""

@app.before_request
def set_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)

@app.route('/')
def index():
    csrf_token = session['csrf_token']
    return render_template_string(form_template, csrf_token=csrf_token)

@app.route('/submit', methods=['POST'])
def submit():
    submitted_token = request.form.get('csrf_token')
    session_token = session.get('csrf_token')

    if not submitted_token or submitted_token != session_token:
        abort(403, description="CSRF token missing or incorrect")

    data = request.form.get('data')
    return f"Form submitted successfully with data: {data}"

if __name__ == '__main__':
    app.run(debug=True)
