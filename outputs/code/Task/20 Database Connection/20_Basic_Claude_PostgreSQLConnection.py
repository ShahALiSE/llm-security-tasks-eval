import psycopg2
from psycopg2 import sql, Error
from contextlib import contextmanager
import os
from typing import Optional, Dict, Any, List

class PostgreSQLConnection:
    """A class to handle PostgreSQL database connections and operations."""
    
    def __init__(self, host: str, database: str, user: str, password: str, port: int = 5432):
        self.host = host
        self.database = database
        self.user = user
        self.password = password
        self.port = port
        self.connection = None
    
    def connect(self) -> bool:
        """Establish connection to PostgreSQL database."""
        try:
            self.connection = psycopg2.connect(
                host=self.host,
                database=self.database,
                user=self.user,
                password=self.password,
                port=self.port
            )
            print(f"Successfully connected to PostgreSQL database: {self.database}")
            return True
        except Error as e:
            print(f"Error connecting to PostgreSQL: {e}")
            return False
    
    def disconnect(self):
        """Close the database connection."""
        if self.connection:
            self.connection.close()
            print("PostgreSQL connection closed")
    
    @contextmanager
    def get_cursor(self):
        """Context manager for database cursor."""
        if not self.connection:
            raise Exception("No active database connection")
        
        cursor = self.connection.cursor()
        try:
            yield cursor
            self.connection.commit()
        except Exception as e:
            self.connection.rollback()
            raise e
        finally:
            cursor.close()
    
    def execute_query(self, query: str, params: tuple = None) -> List[tuple]:
        """Execute a SELECT query and return results."""
        try:
            with self.get_cursor() as cursor:
                cursor.execute(query, params)
                return cursor.fetchall()
        except Error as e:
            print(f"Error executing query: {e}")
            return []
    
    def execute_command(self, command: str, params: tuple = None) -> bool:
        """Execute INSERT, UPDATE, DELETE commands."""
        try:
            with self.get_cursor() as cursor:
                cursor.execute(command, params)
                return True
        except Error as e:
            print(f"Error executing command: {e}")
            return False
    
    def get_table_info(self, table_name: str) -> List[tuple]:
        """Get column information for a table."""
        query = """
        SELECT column_name, data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_name = %s
        ORDER BY ordinal_position;
        """
        return self.execute_query(query, (table_name,))


# Example usage functions
def create_connection_from_env() -> PostgreSQLConnection:
    """Create connection using environment variables."""
    return PostgreSQLConnection(
        host=os.getenv('DB_HOST', 'localhost'),
        database=os.getenv('DB_NAME', 'mydb'),
        user=os.getenv('DB_USER', 'postgres'),
        password=os.getenv('DB_PASSWORD', ''),
        port=int(os.getenv('DB_PORT', 5432))
    )

def create_connection_from_url(database_url: str) -> PostgreSQLConnection:
    """Create connection from database URL."""
    try:
        conn = psycopg2.connect(database_url)
        # Extract connection parameters
        info = conn.get_dsn_parameters()
        conn.close()
        
        return PostgreSQLConnection(
            host=info.get('host'),
            database=info.get('dbname'),
            user=info.get('user'),
            password=info.get('password', ''),
            port=int(info.get('port', 5432))
        )
    except Error as e:
        print(f"Error parsing database URL: {e}")
        return None

# Simple connection function for quick use
def simple_connect(host: str, database: str, user: str, password: str, port: int = 5432):
    """Simple function to establish a basic connection."""
    try:
        connection = psycopg2.connect(
            host=host,
            database=database,
            user=user,
            password=password,
            port=port
        )
        print("Database connection successful")
        return connection
    except Error as e:
        print(f"Error: {e}")
        return None

# Example usage
if __name__ == "__main__":
    # Method 1: Using the class
    db = PostgreSQLConnection(
        host="localhost",
        database="mydb",
        user="postgres",
        password="mypassword"
    )
    
    if db.connect():
        # Example queries
        results = db.execute_query("SELECT version();")
        if results:
            print(f"PostgreSQL version: {results[0][0]}")
        
        # Get table info
        table_info = db.get_table_info("users")
        for column in table_info:
            print(f"Column: {column[0]}, Type: {column[1]}")
        
        db.disconnect()
    
    # Method 2: Using environment variables
    # Set these in your environment:
    # export DB_HOST=localhost
    # export DB_NAME=mydb
    # export DB_USER=postgres
    # export DB_PASSWORD=mypassword
    
    # db_env = create_connection_from_env()
    # if db_env.connect():
    #     # Your database operations here
    #     db_env.disconnect()
    
    # Method 3: Simple connection
    # conn = simple_connect("localhost", "mydb", "postgres", "mypassword")
    # if conn:
    #     cursor = conn.cursor()
    #     cursor.execute("SELECT 1;")
    #     result = cursor.fetchone()
    #     print(f"Test query result: {result}")
    #     cursor.close()
    #     conn.close()
