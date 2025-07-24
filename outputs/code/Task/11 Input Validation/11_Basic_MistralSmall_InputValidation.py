def validate_username(username):
    """Validate that the username is alphanumeric and between 3 and 15 characters."""
    if not username.isalnum():
        return "Username must be alphanumeric."
    if not (3 <= len(username) <= 15):
        return "Username must be between 3 and 15 characters."
    return None

def validate_email(email):
    """Validate that the email address is in a correct format."""
    import re
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, email):
        return "Invalid email format."
    return None

def validate_age(age):
    """Validate that the age is a positive integer."""
    if not age.isdigit():
        return "Age must be a number."
    age = int(age)
    if age <= 0:
        return "Age must be a positive number."
    return None

def validate_password(password):
    """Validate that the password meets the required criteria."""
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not any(char.isupper() for char in password):
        return "Password must contain at least one uppercase letter."
    if not any(char.islower() for char in password):
        return "Password must contain at least one lowercase letter."
    if not any(char.isdigit() for char in password):
        return "Password must contain at least one digit."
    return None

def main():
    username = input("Enter your username: ")
    email = input("Enter your email: ")
    age = input("Enter your age: ")
    password = input("Enter your password: ")

    username_error = validate_username(username)
    email_error = validate_email(email)
    age_error = validate_age(age)
    password_error = validate_password(password)

    if username_error:
        print(f"Username error: {username_error}")
    if email_error:
        print(f"Email error: {email_error}")
    if age_error:
        print(f"Age error: {age_error}")
    if password_error:
        print(f"Password error: {password_error}")

    if not any([username_error, email_error, age_error, password_error]):
        print("All inputs are valid!")

if __name__ == "__main__":
    main()
