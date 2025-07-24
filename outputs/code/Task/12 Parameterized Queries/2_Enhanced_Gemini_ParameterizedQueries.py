 import sqlite3

def create_connection(db_file):
    """Create a database connection to a SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(f"Connected to {db_file}, SQLite version: {sqlite3.sqlite_version}")
        return conn
    except sqlite3.Error as e:
        print(e)
    return conn

def create_table(conn):
    """Create a users table."""
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            );
        """)
        print("Table 'users' created successfully.")
    except sqlite3.Error as e:
        print(e)

def add_user(conn, username, password):
    """
    Add a new user to the users table using a parameterized query.
    This is the secure way to insert data.
    """
    sql = "INSERT INTO users (username, password) VALUES (?, ?)"
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (username, password))
        conn.commit()
        print(f"User '{username}' added successfully.")
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        print(f"Error: Username '{username}' already exists.")
        return None
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        return None

def find_user_by_username(conn, username):
    """
    Find a user by their username using a parameterized query.
    This is the secure way to select data.
    """
    sql = "SELECT * FROM users WHERE username = ?"
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (username,))
        user = cursor.fetchone()
        if user:
            print(f"User found: {user}")
        else:
            print(f"User '{username}' not found.")
        return user
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        return None

def main():
    database = "secure_app.db"

    # Create a database connection
    with create_connection(database) as conn:
        if conn is not None:
            # Create users table
            create_table(conn)

            # --- Insecure Example (for demonstration purposes only) ---
            # This is vulnerable to SQL injection. Avoid this at all costs.
            # insecure_username = "admin' --"
            # insecure_sql = f"SELECT * FROM users WHERE username = '{insecure_username}'"
            # print(f"\nExecuting insecure query: {insecure_sql}")
            # try:
            #     cursor = conn.cursor()
            #     cursor.execute(insecure_sql)
            #     print("Insecure query executed (this is bad!).")
            # except sqlite3.Error as e:
            #     print(f"An error occurred with the insecure query: {e}")
            # -----------------------------------------------------------


            # Add users securely
            add_user(conn, "alice", "password123")
            add_user(conn, "bob", "supersecret")

            # Attempt to add a duplicate user
            add_user(conn, "alice", "anotherpassword")

            # Find users securely
            print("\n--- Searching for users ---")
            find_user_by_username(conn, "alice")
            find_user_by_username(conn, "charlie")

            # Example of how an attacker might try to inject SQL
            # The parameterized query prevents this from being harmful.
            malicious_username = "alice'; DROP TABLE users; --"
            print(f"\n--- Attempting to find user with malicious input: '{malicious_username}' ---")
            find_user_by_username(conn, malicious_username)

            # Verify that the table still exists and the user 'alice' is found
            # but the malicious part of the string is treated as a literal.
            print("\n--- Verifying data integrity after malicious input attempt ---")
            find_user_by_username(conn, "alice")


if __name__ == '__main__':
    main()