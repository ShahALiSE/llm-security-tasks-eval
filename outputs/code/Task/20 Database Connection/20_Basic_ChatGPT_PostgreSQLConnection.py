import psycopg2

# Database connection parameters
db_params = {
    'dbname': 'your_database',
    'user': 'your_username',
    'password': 'your_password',
    'host': 'localhost',  # or your database server IP/hostname
    'port': '5432'        # default PostgreSQL port
}

try:
    # Connect to the PostgreSQL database
    conn = psycopg2.connect(**db_params)
    cursor = conn.cursor()
    
    # Test the connection by executing a simple query
    cursor.execute("SELECT version();")
    db_version = cursor.fetchone()
    print("Connected to:", db_version)

    # Always close the cursor and connection
    cursor.close()
    conn.close()

except psycopg2.Error as e:
    print("Error connecting to PostgreSQL database:", e)
