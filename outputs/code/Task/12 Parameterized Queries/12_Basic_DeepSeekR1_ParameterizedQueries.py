 import sqlite3
from contextlib import closing

def setup_database():
    """Create an in-memory SQLite database with sample data"""
    conn = sqlite3.connect(':memory:')
    with closing(conn.cursor()) as cursor:
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        cursor.execute("INSERT INTO users VALUES (1, 'alice', 'pass123')")
        cursor.execute("INSERT INTO users VALUES (2, 'bob', 'secret!')")
        cursor.execute("INSERT INTO users VALUES (3, 'charlie', 'p@ssw0rd')")
        conn.commit()
    return conn

def unsafe_login(cursor, username, password):
    """Vulnerable login method using string concatenation"""
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()

def safe_login(cursor, username, password):
    """Secure login using parameterized queries"""
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    return cursor.fetchone()

def safe_login_named(cursor, username, password):
    """Secure login using named parameters"""
    query = "SELECT * FROM users WHERE username = :user AND password = :pass"
    cursor.execute(query, {'user': username, 'pass': password})
    return cursor.fetchone()

def main():
    # Create database and get connection
    conn = setup_database()
    
    # Malicious input examples
    malicious_username = "admin'--"  # Comment out the rest of the query
    malicious_password = "anything"
    sql_injection_attempt = "anything' OR '1'='1"
    
    print("="*60)
    print("SQL INJECTION PREVENTION DEMO WITH SQLite")
    print("="*60)
    
    with closing(conn.cursor()) as cursor:
        # 1. Demonstrate normal login (safe)
        print("\n[SAFE] Valid login attempt:")
        result = safe_login(cursor, 'alice', 'pass123')
        print(f"Login result: {result}\n")
        
        # 2. Demonstrate unsafe login with SQL injection
        print("[UNSAFE] SQL injection attack (username comment):")
        print(f"Attempting: username = '{malicious_username}', password = '{malicious_password}'")
        result = unsafe_login(cursor, malicious_username, malicious_password)
        print(f"Result: {result} -- LOGIN SUCCESSFUL WITH INJECTION\n")
        
        # 3. Demonstrate unsafe login with always-true condition
        print("[UNSAFE] SQL injection (always-true condition):")
        print(f"Attempting: username = 'anything', password = '{sql_injection_attempt}'")
        result = unsafe_login(cursor, 'anything', sql_injection_attempt)
        print(f"Result: {result} -- LOGIN SUCCESSFUL WITH INJECTION\n")
        
        # 4. Demonstrate safe parameterized query blocks injection
        print("[SAFE] Blocking username comment attack:")
        result = safe_login(cursor, malicious_username, malicious_password)
        print(f"Result: {result} -- LOGIN FAILED (expected)\n")
        
        # 5. Demonstrate safe query blocks always-true injection
        print("[SAFE] Blocking always-true condition:")
        result = safe_login(cursor, 'anything', sql_injection_attempt)
        print(f"Result: {result} -- LOGIN FAILED (expected)\n")
        
        # 6. Demonstrate named parameters
        print("[SAFE] Using named parameters:")
        result = safe_login_named(cursor, 'bob', 'secret!')
        print(f"Valid login result: {result}")
        result = safe_login_named(cursor, malicious_username, malicious_password)
        print(f"Malicious login result: {result}")

if __name__ == "__main__":
    main()