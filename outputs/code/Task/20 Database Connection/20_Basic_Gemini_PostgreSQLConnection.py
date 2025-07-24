import psycopg2
import os

def connect_to_db():
    """
    Connects to the PostgreSQL database and returns the connection object.
    """
    conn = None
    try:
        # It's recommended to use environment variables for connection details
        conn = psycopg2.connect(
            host=os.environ.get("DB_HOST", "localhost"),
            database=os.environ.get("DB_NAME", "your_db_name"),
            user=os.environ.get("DB_USER", "your_username"),
            password=os.environ.get("DB_PASSWORD", "your_password")
        )

        # Create a cursor to perform database operations
        cur = conn.cursor()

        # Print the PostgreSQL version
        print("PostgreSQL database version:")
        cur.execute("SELECT version()")
        db_version = cur.fetchone()
        print(db_version)

        # Close the cursor
        cur.close()

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"Error while connecting to PostgreSQL: {error}")

    finally:
        if conn is not None:
            conn.close()
            print("Database connection closed.")

if __name__ == '__main__':
    # For demonstration purposes, you can set these environment variables
    # in your terminal before running the script. For example:
    # export DB_NAME="testdb"
    # export DB_USER="testuser"
    # export DB_PASSWORD="testpassword"
    connect_to_db()