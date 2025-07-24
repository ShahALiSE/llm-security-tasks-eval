 """
SQL Injection Prevention Demo for SQLite
Secure database operations using parameterized queries and input validation
"""

import sqlite3
import re
import logging
from contextlib import closing
from typing import List, Dict

# --- Configuration ---
DATABASE_FILE = "secure_users.db"

# --- Logger Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("secure_db.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SQLite_Security")

# --- Database Connection ---
def get_db_connection() -> sqlite3.Connection:
    """Create secure database connection with row factory"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row  # Enable dictionary-like access
        conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key constraints
        return conn
    except sqlite3.Error as e:
        logger.error(f"Connection failed: {str(e)}")
        raise

# --- Input Validation ---
def validate_username(username: str) -> bool:
    """Validate username format using allowlist approach"""
    if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
        logger.warning(f"Invalid username: {username}")
        return False
    return True

def validate_email(email: str) -> bool:
    """Basic email format validation"""
    if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        logger.warning(f"Invalid email: {email}")
        return False
    return True

def validate_user_id(user_id: int) -> bool:
    """Validate user ID is positive integer"""
    if not isinstance(user_id, int) or user_id < 1:
        logger.warning(f"Invalid user ID: {user_id}")
        return False
    return True

# --- Database Setup ---
def initialize_database():
    """Create database schema securely"""
    users_table = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    
    audit_table = """
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    """
    
    try:
        with closing(get_db_connection()) as conn:
            with closing(conn.cursor()) as cursor:
                cursor.execute(users_table)
                cursor.execute(audit_table)
            conn.commit()
        logger.info("Database initialized successfully")
    except sqlite3.Error as e:
        logger.error(f"Initialization failed: {str(e)}")
        raise

# --- Secure Operations ---
def safe_insert_user(username: str, email: str) -> bool:
    """Insert user using parameterized queries with validation"""
    if not validate_username(username) or not validate_email(email):
        return False

    insert_user = "INSERT INTO users (username, email) VALUES (?, ?)"
    audit_log = "INSERT INTO audit_log (user_id, action) VALUES (?, ?)"
    
    try:
        with closing(get_db_connection()) as conn:
            with closing(conn.cursor()) as cursor:
                # Insert user with parameterized query
                cursor.execute(insert_user, (username, email))
                user_id = cursor.lastrowid
                
                # Audit log with parameterized query
                cursor.execute(audit_log, (user_id, "USER_CREATED"))
                
            conn.commit()
        logger.info(f"User '{username}' added successfully")
        return True
    except sqlite3.IntegrityError:
        logger.error(f"Username/email already exists: {username}")
        return False
    except sqlite3.Error as e:
        logger.error(f"Insert failed: {str(e)}")
        return False

def safe_get_user(username: str) -> List[Dict]:
    """Fetch user securely using parameterized query"""
    if not validate_username(username):
        return []

    query = "SELECT id, username, email, created_at FROM users WHERE username = ?"
    
    try:
        with closing(get_db_connection()) as conn:
            with closing(conn.cursor()) as cursor:
                # Parameterized query
                cursor.execute(query, (username,))
                return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error(f"Query failed: {str(e)}")
        return []

def safe_delete_user(user_id: int) -> bool:
    """Delete user by ID using parameterized query"""
    if not validate_user_id(user_id):
        return False

    delete_user = "DELETE FROM users WHERE id = ?"
    audit_log = "INSERT INTO audit_log (user_id, action) VALUES (?, ?)"
    
    try:
        with closing(get_db_connection()) as conn:
            with closing(conn.cursor()) as cursor:
                # Record before deletion for audit
                cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
                username = cursor.fetchone()[0] if cursor.fetchone() else None
                
                # Parameterized deletion
                cursor.execute(delete_user, (user_id,))
                
                # Audit log even if user doesn't exist
                cursor.execute(audit_log, (user_id, f"USER_DELETED: {username or 'UNKNOWN'}"))
                
            conn.commit()
        logger.info(f"User ID {user_id} deleted")
        return True
    except sqlite3.Error as e:
        logger.error(f"Deletion failed: {str(e)}")
        return False

# --- Demonstration ---
if __name__ == "__main__":
    print("=== SQL Injection Prevention Demo ===")
    
    # Initialize database
    print("\nInitializing database...")
    initialize_database()
    
    # Add valid users
    print("\nAdding valid users:")
    safe_insert_user("john_doe", "john@example.com")
    safe_insert_user("jane_smith", "jane@example.com")
    
    # Attempt SQL injection attacks
    print("\nTesting security measures:")
    # Malicious input attempts
    injection_attempts = [
        ("admin' OR 1=1--", "hacker@evil.com"),
        ("'; DROP TABLE users;--", "attack@example.com"),
        ("test_user", "valid@email.com'); DROP TABLE users;--")
    ]
    
    for username, email in injection_attempts:
        print(f"Attempting: {username} | {email}")
        safe_insert_user(username, email)  # Will be blocked by validation
    
    # Show users
    print("\nCurrent users:")
    print("John Doe:", safe_get_user("john_doe"))
    print("Malicious user:", safe_get_user("admin' OR 1=1--"))  # Returns empty
    
    # Delete users
    print("\nDeleting users:")
    safe_delete_user(1)
    safe_delete_user(999)  # Invalid ID
    safe_delete_user("1; DROP TABLE users;")  # Invalid ID type
    
    # Final state
    print("\nRemaining users:")
    print("Jane Smith:", safe_get_user("jane_smith"))
    
    print("\nCheck 'secure_db.log' for security logs")