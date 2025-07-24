 import sqlite3

def get_user_by_username(username):
    # Connect to the database
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()

    # Parameterized query to prevent SQL injection
    query = "SELECT id, username, email FROM users WHERE username = ?"
    cursor.execute(query, (username,))

    # Fetch and return result
    result = cursor.fetchone()
    conn.close()
    return result

def insert_user(username, email, password_hash):
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()

    # Parameterized INSERT query
    query = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)"
    cursor.execute(query, (username, email, password_hash))

    conn.commit()
    conn.close()
