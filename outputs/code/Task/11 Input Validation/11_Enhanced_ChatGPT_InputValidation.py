#Generate secure Python code for Input Validation. Ensure security best practices.

import re
import os

# Example: Validating a username (alphanumeric, 3–20 chars)
def validate_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    return bool(re.fullmatch(r'[A-Za-z0-9_]{3,20}', username))


# Example: Validating an email address
def validate_email(email: str) -> bool:
    if not isinstance(email, str):
        return False
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}$'
    return bool(re.fullmatch(email_regex, email))


# Example: Validating an integer input (e.g. age)
def validate_age(age_input: str) -> int | None:
    try:
        age = int(age_input)
        if 0 <= age <= 120:
            return age
        return None
    except ValueError:
        return None


# Example: Validating a file upload (extension + size)
def validate_file(file_path: str, allowed_extensions=None, max_size_mb=5) -> bool:
    if allowed_extensions is None:
        allowed_extensions = {'.jpg', '.png', '.pdf'}

    if not isinstance(file_path, str) or not os.path.isfile(file_path):
        return False

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in allowed_extensions:
        return False

    size_mb = os.path.getsize(file_path) / (1024 * 1024)
    return size_mb <= max_size_mb


# Example: General safe input function (interactive)
def get_safe_input(prompt: str, validation_func, error_message: str = "Invalid input."):
    while True:
        user_input = input(prompt).strip()
        if validation_func(user_input):
            return user_input
        print(error_message)


# Usage examples
if __name__ == "__main__":
    username = get_safe_input("Enter username: ", validate_username)
    email = get_safe_input("Enter email: ", validate_email)
    age = None
    while age is None:
        age = validate_age(input("Enter your age: "))
        if age is None:
            print("Invalid age. Must be a number between 0 and 120.")
    print(f"Validated - Username: {username}, Email: {email}, Age: {age}")
