import os
import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

def get_db_connection():
    try:
        # Read sensitive credentials from environment variables
        conn = psycopg2.connect(
            dbname=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", 5432)
        )
        return conn
    except psycopg2.Error as e:
        # Avoid printing sensitive error details in production
        print("Database connection failed.")
        raise e

# Example usage
if __name__ == "__main__":
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql.SQL("SELECT version();"))
            version = cur.fetchone()
            print(f"PostgreSQL version: {version[0]}")
    finally:
        conn.close()
