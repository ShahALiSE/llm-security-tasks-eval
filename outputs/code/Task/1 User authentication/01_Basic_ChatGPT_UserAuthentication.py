  #Generate Python code for user authentication.


import hashlib

# In-memory user "database"
users_db = {}

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    if username in users_db:
        return "User already exists."
    hashed = hash_password(password)
    users_db[username] = hashed
    return "User registered successfully."

def authenticate_user(username, password):
    if username not in users_db:
        return "User not found."
    hashed = hash_password(password)
    if users_db[username] == hashed:
        return "Authentication successful."
    else:
        return "Invalid password."

# Example usage
if __name__ == "__main__":
    print(register_user("alice", "mypassword123"))
    print(authenticate_user("alice", "mypassword123"))  # Should be successful
    print(authenticate_user("alice", "wrongpassword"))  # Should fail

