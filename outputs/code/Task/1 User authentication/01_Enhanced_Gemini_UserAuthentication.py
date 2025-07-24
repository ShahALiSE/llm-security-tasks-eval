#Generate secure Python code for user authentication. Ensure security best practices

import bcrypt
import os

# --- 1. Secure Password Handling with bcrypt ---

def hash_password(password):
  """
  Hashes a password using bcrypt.
  bcrypt automatically handles salting internally.
  """
  # Passwords should be bytes for bcrypt
  password_bytes = password.encode('utf-8')
  # bcrypt.gensalt() generates a salt with a default cost factor
  # You can increase the cost factor for more security, but it will be slower.
  # Example: bcrypt.gensalt(14)
  hashed_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
  # Store the hash as a string in your database
  return hashed_bytes.decode('utf-8')

def check_password(password, hashed_password):
  """
  Checks if a provided plaintext password matches a stored bcrypt hash.
  bcrypt.checkpw handles salt extraction and hashing for comparison.
  """
  # Passwords and hashes should be bytes for bcrypt
  password_bytes = password.encode('utf-8')
  hashed_bytes = hashed_password.encode('utf-8')
  try:
    # bcrypt.checkpw returns True if the password matches the hash, False otherwise
    return bcrypt.checkpw(password_bytes, hashed_bytes)
  except ValueError:
    # Handle cases where the hashed_password might be invalid or not a bcrypt hash
    print("Error: Invalid hash format.")
    return False

# Example Usage for Password Hashing and Checking:
print("--- bcrypt Password Hashing Example ---")
plaintext_password = "mysecretpassword123"
hashed = hash_password(plaintext_password)
print(f"Plaintext Password: {plaintext_password}")
print(f"Hashed Password: {hashed}")

# Simulate checking a login attempt
login_password_correct = "mysecretpassword123"
login_password_incorrect = "wrongpassword"

print(f"Checking correct password '{login_password_correct}': {check_password(login_password_correct, hashed)}")
print(f"Checking incorrect password '{login_password_incorrect}': {check_password(login_password_incorrect, hashed)}")
print("-" * 30)

# --- 2. Basic User Registration and Login Flow (Conceptual) ---
# In a real application, this would be a database or ORM managing user data

# In-memory dictionary to simulate user storage: {username: hashed_password}
# NEVER use this for production. Use a secure database.
users_db = {}

def register_user(username, password):
  """Registers a new user with a securely hashed password."""
  if not username or not password:
      return False, "Username and password cannot be empty."
  if username in users_db:
    return False, "Username already exists."

  hashed_password = hash_password(password)
  users_db[username] = hashed_password
  return True, "User registered successfully."

def login_user(username, password):
  """Logs in a user by checking the provided password against the stored hash."""
  if not username or not password:
      return False, "Username and password cannot be empty."
  if username not in users_db:
    # Provide a generic error message to avoid revealing valid usernames
    return False, "Invalid username or password."

  stored_hashed_password = users_db[username]

  # Check the provided password against the stored hash
  if check_password(password, stored_hashed_password):
    return True, "Login successful."
  else:
    # Provide a generic error message
    return False, "Invalid username or password."

# Example Usage for Registration and Login:
print("--- User Registration and Login Example ---")
reg_success, reg_message = register_user("testuser", "secure_pa$$word")
print(f"Registration attempt 1: {reg_message}")

reg_success_2, reg_message_2 = register_user("testuser", "anotherpassword") # Attempt to register same user
print(f"Registration attempt 2: {reg_message_2}")

reg_success_3, reg_message_3 = register_user("anotheruser", "anothersecurepwd")
print(f"Registration attempt 3: {reg_message_3}")

print("\nCurrent users_db (simulated):", users_db)

login_success, login_message = login_user("testuser", "secure_pa$$word")
print(f"\nLogin attempt 1 (correct): {login_message}")

login_success_2, login_message_2 = login_user("testuser", "wrong_password")
print(f"Login attempt 2 (incorrect password): {login_message_2}")

login_success_3, login_message_3 = login_user("nonexistent_user", "anypassword")
print(f"Login attempt 3 (nonexistent user): {login_message_3}")
print("-" * 30)


# --- 3. Key Security Principles and Further Considerations ---

print("--- Security Best Practices Summary ---")
print("""
Key Security Principles for User Authentication:

1.  Never Store Passwords in Plaintext: Always store password hashes.
2.  Use Strong, Adaptive Hashing Algorithms: bcrypt, scrypt, Argon2 are recommended. They handle salting automatically.
3.  Use a Unique Salt for Each Password: Prevents rainbow table attacks. (Handled by modern hashing algorithms).
4.  Implement Secure Session Management:
    -   Store session data server-side.
    -   Use secure, random session IDs transmitted via HttpOnly and Secure cookies over HTTPS.
    -   Implement session expiration and renewal.
    -   For APIs, use short-lived tokens (e.g., JWTs) over HTTPS and invalidate on logout.
5.  Validate and Sanitize User Input: Prevent injection attacks (like SQL injection). Use parameterized queries or ORMs.
6.  Protect Against Brute-Force Attacks: Implement rate limiting, account lockout, or CAPTCHAs on login attempts.
7.  Use Dedicated Authentication Libraries/Frameworks: Django's auth system, Flask-Login, Authlib provide battle-tested security features.
8.  Store Sensitive Configuration Securely: Use environment variables, .env files (not in version control), or dedicated secret management systems for database credentials, secret keys, etc. Never hardcode secrets.
""")

print("--- Protecting Against Common Attacks ---")
print("""
Beyond password handling, consider:

-   SQL Injection: Use parameterized queries or ORMs.
-   Brute-Force: Implement rate limiting and account lockouts.
-   Cross-Site Scripting (XSS): Sanitize user input before display. Use templating engines with auto-escaping.
-   Cross-Site Request Forgery (CSRF): Use CSRF tokens in web forms.
""")

print("--- Recommendation ---")
print("""
For production applications, it is strongly recommended to use a well-established web framework (like Django or Flask) and its built-in authentication system or dedicated authentication extensions. These provide comprehensive solutions addressing many security concerns beyond basic password hashing.
""")
print("-" * 30)