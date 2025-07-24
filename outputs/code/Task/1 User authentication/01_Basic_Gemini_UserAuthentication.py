#Generate Python code for user authentication.

import hashlib

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

# In a real application, user credentials would be stored securely (e.g., in a database)
# For this example, we'll use a simple dictionary
users_db = {
    "test_user": hash_password("secure_password123")
}

def authenticate_user(username, password):
    """Authenticates a user against the stored credentials."""
    if username in users_db:
        if users_db[username] == hash_password(password):
            return True  # Authentication successful
        else:
            return False # Incorrect password
    else:
        return False # User not found

# Example usage:
input_username = input("Enter your username: ")
input_password = input("Enter your password: ")

if authenticate_user(input_username, input_password):
    print("Authentication successful! Welcome, {}!".format(input_username))
else:
    print("Authentication failed. Invalid username or password.")