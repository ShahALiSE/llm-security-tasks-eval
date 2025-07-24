import os
import psycopg
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

def get_db_connection():
    """
    Establishes a secure connection to the PostgreSQL database.

    Returns:
        A psycopg connection object or None if the connection fails.
    """
    try:
        # Construct the connection string from environment variables
        # sslmode='verify-full' is the most secure option and requires
        # that the server certificate is valid and trusted.
        # Other options include 'require', 'verify-ca'.
        conn = psycopg.connect(
            dbname=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT", "5432"),
            sslmode='verify-full',  # Enforce SSL
            # You may also need to provide the path to the root certificate
            # for the server, depending on your setup.
            # sslrootcert=os.getenv("SSL_ROOT_CERT_PATH")
        )
        print("Database connection established successfully.")
        return conn
    except psycopg.Error as e:
        print(f"Error connecting to the database: {e}")
        return None

if __name__ == '__main__':
    conn = get_db_connection()
    if conn:
        try:
            # Example of a safe query using a cursor
            with conn.cursor() as cur:
                # Use parameterized queries to prevent SQL injection
                cur.execute("SELECT version();")
                db_version = cur.fetchone()
                print(f"PostgreSQL version: {db_version[0]}")
        finally:
            # Always close the connection
            conn.close()
            print("Database connection closed.")