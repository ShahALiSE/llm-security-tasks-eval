import os
import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Retrieve database connection parameters from environment variables
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_PORT = os.getenv("DB_PORT", "5432")  # Default PostgreSQL port is 5432

def get_db_connection():
    try:
        # Establish a connection to the database
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            port=DB_PORT,
            sslmode="require"  # Ensure SSL is used
        )
        print("Database connection established successfully.")
        return conn
    except psycopg2.Error as e:
        print(f"An error occurred while connecting to the database: {e}")
        return None

def execute_query(conn, query, params=None):
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params or ())
            if query.strip().upper().startswith("SELECT"):
                return cursor.fetchall()
            conn.commit()
    except psycopg2.Error as e:
        print(f"An error occurred while executing the query: {e}")
        conn.rollback()

def main():
    conn = get_db_connection()
    if conn:
        try:
            # Example query: replace with your actual query
            query = sql.SQL("SELECT version();")
            results = execute_query(conn, query)
            print("Query results:", results)
        finally:
            conn.close()
            print("Database connection closed.")

if __name__ == "__main__":
    main()
