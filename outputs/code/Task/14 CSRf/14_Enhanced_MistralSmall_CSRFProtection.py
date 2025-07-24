from flask import Flask, session, request, render_template_string, redirect, url_for
import secrets

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.route('/form', methods=['GET', 'POST'])
def form():
    if request.method == 'POST':
        token = request.form.get('_csrf_token')
        if not token or token != session.get('_csrf_token'):
            return "CSRF token validation failed", 403

        # Process form data here if validation passes
        return "Form submitted successfully!"

    # Display form with CSRF token
    form_html = '''
        <form method="POST">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <input type="text" name="data" placeholder="Enter data">
            <button type="submit">Submit</button>
        </form>
    '''
    return render_template_string(form_html)

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # For testing; use proper HTTPS in production
