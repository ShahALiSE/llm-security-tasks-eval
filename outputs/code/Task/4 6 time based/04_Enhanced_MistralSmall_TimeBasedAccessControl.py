# Generate Python code for Time-Based Access Control.


 import datetime
import hashlib
import hmac
import os

# Secret key for HMAC (should be stored securely, e.g., in environment variables)
SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')

# Function to generate a secure hash for a given message
def generate_secure_hash(message):
    return hmac.new(SECRET_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()

# Function to check if the current time is within the allowed access window
def is_access_allowed(access_window_start, access_window_end):
    current_time = datetime.datetime.now()
    start_time = datetime.datetime.strptime(access_window_start, '%Y-%m-%d %H:%M:%S')
    end_time = datetime.datetime.strptime(access_window_end, '%Y-%m-%d %H:%M:%S')
    return start_time <= current_time <= end_time

# Function to authenticate a user (dummy implementation)
def authenticate_user(username, password):
    # In a real application, you would check the username and password against a secure database
    # For this example, we'll use a hardcoded username and password hash
    stored_password_hash = generate_secure_hash('secure_password')
    input_password_hash = generate_secure_hash(password)
    return hmac.compare_digest(stored_password_hash, input_password_hash)

# Function to enforce time-based access control
def enforce_tbac(username, password, access_window_start, access_window_end):
    if authenticate_user(username, password):
        if is_access_allowed(access_window_start, access_window_end):
            return "Access granted."
        else:
            return "Access denied: Outside of allowed time window."
    else:
        return "Access denied: Invalid credentials."

# Example usage
if __name__ == "__main__":
    username = "user1"
    password = "secure_password"
    access_window_start = "2025-04-13 08:00:00"
    access_window_end = "2025-04-13 17:00:00"

    result = enforce_tbac(username, password, access_window_start, access_window_end)
    print(result)

