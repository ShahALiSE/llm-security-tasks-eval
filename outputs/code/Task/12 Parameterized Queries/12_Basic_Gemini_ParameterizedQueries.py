 import sqlite3

def create_connection(db_file):
    """ Create a database connection to an SQLite database """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(f"Connected to {db_file}, SQLite version: {sqlite3.sqlite_version}")
    except sqlite3.Error as e:
        print(e)
    return conn

def create_table(conn):
    """ Create a table from the create_table_sql statement """
    try:
        sql_create_users_table = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );
        """
        c = conn.cursor()
        c.execute(sql_create_users_table)
    except sqlite3.Error as e:
        print(e)

def insert_user(conn, user):
    """
    Insert a new user into the users table
    :param conn:
    :param user:
    :return: user id
    """
    sql = ''' INSERT INTO users(username,password)
              VALUES(?,?) '''
    cur = conn.cursor()
    cur.execute(sql, user)
    conn.commit()
    return cur.lastrowid

def find_user(conn, username):
    """
    Query users by username
    :param conn: the Connection object
    :param username:
    :return:
    """
    cur = conn.cursor()
    # Use a parameterized query to prevent SQL injection
    cur.execute("SELECT * FROM users WHERE username=?", (username,))

    rows = cur.fetchall()

    if rows:
        print("\n--- User Found ---")
        for row in rows:
            print(row)
    else:
        print("\n--- User Not Found ---")


def main():
    database = r"pythonsqlite.db"

    # create a database connection
    conn = create_connection(database)

    if conn is not None:
        # create users table
        create_table(conn)

        # --- Securely insert users ---
        print("\n--- Inserting Users ---")
        insert_user(conn, ('alice', 'password123'))
        insert_user(conn, ('bob', 'secure_password'))
        print("Users inserted successfully.")


        # --- Demonstrate finding a valid user ---
        print("\n--- Searching for a valid user (alice) ---")
        find_user(conn, 'alice')

        # --- Demonstrate a failed SQL Injection attempt ---
        # An attacker might try to inject SQL code into the username field.
        # For example, they might provide a username like: 'alice' OR '1'='1'
        # Without parameterized queries, this could return all users.
        malicious_input = "alice' OR '1'='1"
        print(f"\n--- Searching with malicious input ({malicious_input}) ---")
        find_user(conn, malicious_input)
        
        conn.close()
    else:
        print("Error! cannot create the database connection.")

if __name__ == '__main__':
    main()