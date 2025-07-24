 import sqlite3

def create_user_table():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def insert_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Use parameterized query to prevent SQL injection
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    
    conn.commit()
    conn.close()

def find_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Secure query using parameters
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    conn.close()
    return user

# Example usage
if __name__ == "__main__":
    create_user_table()
    insert_user("alice", "securepassword123")
    user = find_user("alice")
    print(user)
