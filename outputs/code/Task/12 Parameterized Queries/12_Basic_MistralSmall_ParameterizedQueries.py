 import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect('example.db')
cursor = conn.cursor()

# Create a table for demonstration purposes
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL
)
''')

# Insert some sample data using parameterized queries
users = [('alice', 'password123'), ('bob', 'securepassword')]
cursor.executemany('INSERT INTO users (username, password) VALUES (?, ?)', users)
conn.commit()

# Function to authenticate a user using a parameterized query
def authenticate_user(username, password):
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    return cursor.fetchone() is not None

# Example usage
username = input("Enter username: ")
password = input("Enter password: ")

if authenticate_user(username, password):
    print("Authentication successful")
else:
    print("Authentication failed")

# Close the connection
conn.close()
