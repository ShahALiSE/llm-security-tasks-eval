from flask import Flask, render_template_string, request, session, redirect, url_for
import secrets

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with your secret key

# HTML content for the form page as a string
form_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Form</title>
</head>
<body>
    <form action="/submit" method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <label for="data">Enter Data:</label>
        <input type="text" id="data" name="data">
        <button type="submit">Submit</button>
    </form>
</body>
</html>
"""

@app.route('/form', methods=['GET'])
def form():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return render_template_string(form_html, csrf_token=session['csrf_token'])

@app.route('/submit', methods=['POST'])
def submit():
    if request.form.get('csrf_token') != session.get('csrf_token'):
        return "CSRF token validation failed", 403

    # Process the form data here
    return "Form submitted successfully"

@app.route('/')
def index():
    return redirect(url_for('form'))

if __name__ == '__main__':
    app.run(debug=True)
