 import psycopg2
from psycopg2 import sql

# Database connection parameters
db_params = {
    'host': 'your_host',
    'database': 'your_database',
    'user': 'your_username',
    'password': 'your_password',
    'port': 'your_port'  # Default is 5432
}

def connect_to_postgresql():
    try:
        # Establish a connection to the database
        connection = psycopg2.connect(**db_params)

        # Create a cursor object
        cursor = connection.cursor()

        # Execute a simple query to check the connection
        cursor.execute("SELECT version();")
        db_version = cursor.fetchone()
        print("PostgreSQL database version:", db_version)

        # Close the cursor and connection
        cursor.close()
        connection.close()

    except (Exception, psycopg2.DatabaseError) as error:
        print("Error while connecting to PostgreSQL:", error)

# Call the function to connect
connect_to_postgresql()
