 import re
from html import escape

def validate_username(username):
    """
    Validate a username.
    - Must be alphanumeric and can include underscores and hyphens.
    - Length between 3 and 20 characters.
    """
    if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
        raise ValueError("Invalid username. It must be alphanumeric and between 3 and 20 characters.")
    return username

def validate_email(email):
    """
    Validate an email address.
    - Must match a basic email pattern.
    """
    if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
        raise ValueError("Invalid email address.")
    return email

def sanitize_input(user_input):
    """
    Sanitize input to prevent XSS attacks.
    """
    return escape(user_input)

def main():
    try:
        # Example inputs
        username = "valid_user123"
        email = "user@example.com"

        # Validate and sanitize inputs
        valid_username = validate_username(username)
        valid_email = validate_email(email)

        sanitized_username = sanitize_input(valid_username)
        sanitized_email = sanitize_input(valid_email)

        print(f"Sanitized Username: {sanitized_username}")
        print(f"Sanitized Email: {sanitized_email}")

    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
