  #Generate secure Python code for user authentication. Ensure security best practices


  import sqlite3
import bcrypt

# Initialize the database and create user table (only once)
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Register a new user
def register_user(username: str, password: str) -> bool:
    if not username or not password:
        print("Username and password cannot be empty.")
        return False

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                       (username, password_hash))
        conn.commit()
        print("User registered successfully.")
        return True
    except sqlite3.IntegrityError:
        print("Username already exists.")
        return False
    finally:
        conn.close()

# Authenticate a user
def authenticate_user(username: str, password: str) -> bool:
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        print("User not found.")
        return False

    stored_hash = row[0]

    if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        print("Authentication successful.")
        return True
    else:
        print("Invalid password.")
        return False

# Example usage
if __name__ == '__main__':
    init_db()
    # register_user("alice", "secure_password123")
    # authenticate_user("alice", "secure_password123")
