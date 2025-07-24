# main.py
# Description: A simple Flask web application demonstrating CSRF protection
# using the Flask-WTF extension.
#
# Installation:
# pip install Flask Flask-WTF
#
# To Run:
# python main.py
# Then open http://127.0.0.1:5000 in your browser.

import os
from flask import Flask, render_template_string, request, flash

# Flask-WTF provides form handling, including CSRF protection.
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect

# --- Flask App Setup ---
app = Flask(__name__)

# A secret key is required for session management and CSRF token generation.
# In a real application, load this from an environment variable or a secure config.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-secure-and-random-secret-key')

# Initialize CSRF protection for the entire application.
# This extension will handle generating and validating tokens automatically.
csrf = CSRFProtect(app)


# --- Form Definition ---
class SimpleForm(FlaskForm):
    """
    A simple web form using Flask-WTF.
    It includes a text field for a name and a submit button.
    Flask-WTF automatically adds a hidden CSRF token field to this form.
    """
    name = StringField('Name:', validators=[DataRequired()])
    submit = SubmitField('Submit')


# --- HTML Template ---
# Using a string for simplicity, but this would typically be in a .html file.
HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Flask CSRF Protection Example</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 40px; background-color: #f8f9fa; color: #333; }
        .container { max-width: 600px; margin: 0 auto; background-color: #fff; padding: 20px 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #0056b3; }
        form { margin-top: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"] { width: 100%; padding: 8px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 4px; }
        input[type="submit"] { background-color: #007bff; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        input[type="submit"]:hover { background-color: #0056b3; }
        .flash { padding: 15px; margin-top: 20px; border-radius: 4px; background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CSRF Protection with Flask-WTF</h1>
        <p>Submit this form. The request will only succeed if the hidden CSRF token is valid.</p>
        
        <!-- Flash messages display feedback from the server -->
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <div class="flash">
            {% for message in messages %}
              {{ message }}
            {% endfor %}
            </div>
          {% endif %}
        {% endwith %}

        <!-- The form is rendered here -->
        <form method="POST" action="/">
            <!-- This is the most important part for CSRF protection. -->
            <!-- It renders a hidden input with the CSRF token. -->
            {{ form.csrf_token }}
            
            {{ form.name.label }}
            {{ form.name(size=20) }}
            
            {{ form.submit() }}
        </form>
    </div>
</body>
</html>
"""


# --- View Function ---
@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Handles both GET and POST requests for the main page.
    """
    form = SimpleForm()
    
    # form.validate_on_submit() checks if it's a POST request AND if the CSRF token is valid.
    # If the token is missing or incorrect, it will return False and the request is rejected.
    if form.validate_on_submit():
        # This block only executes on a successful POST with a valid token.
        user_name = form.name.data
        flash(f'Success! CSRF token validated for user: {user_name}')
        # In a real app, you would process the data here (e.g., save to a database).
        
    # For both GET requests and failed POST requests, render the page with the form.
    return render_template_string(HTML_TEMPLATE, form=form)


# --- Run Application ---
if __name__ == '__main__':
    print("Flask server running. Access at http://127.0.0.1:5000")
    print("Try submitting the form normally.")
    print("To see protection in action, try disabling the csrf_token field in your browser's dev tools and resubmitting.")
    app.run(debug=True)
