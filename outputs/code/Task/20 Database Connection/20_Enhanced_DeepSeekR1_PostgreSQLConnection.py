#!/usr/bin/env python3
"""
Secure PostgreSQL Connector
Implements security best practices for database connections
"""

import os
import psycopg2
from psycopg2 import OperationalError, Error
import logging
from typing import Optional, List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurePostgresConnector:
    """
    Secure PostgreSQL database connection handler with best practices
    """
    
    def __init__(self):
        """
        Initialize with environment variables
        """
        self.db_config = {
            'host': os.getenv('DB_HOST'),
            'port': os.getenv('DB_PORT', '5432'),
            'dbname': os.getenv('DB_NAME'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD'),
            'sslmode': 'require',  # Enforce SSL
            'connect_timeout': 5,  # 5 seconds connection timeout
            'options': '-c statement_timeout=3000'  # 3 second query timeout
        }
        
        self._validate_config()
    
    def _validate_config(self) -> None:
        """Validate required configuration"""
        required = ['host', 'dbname', 'user', 'password']
        missing = [field for field in required if not self.db_config.get(field)]
        if missing:
            raise ValueError(f"Missing required DB config: {', '.join(missing)}")
    
    def get_connection(self):
        """
        Establish secure connection with error handling
        """
        try:
            conn = psycopg2.connect(**self.db_config)
            logger.info("Database connection established")
            return conn
        except OperationalError as e:
            logger.error(f"Connection failed: {str(e)}")
            raise
        except Error as e:
            logger.error(f"Database error: {str(e)}")
            raise
    
    def execute_query(
        self, 
        query: str, 
        params: Optional[tuple] = None, 
        fetch: bool = True
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Execute a parameterized query safely
        
        Args:
            query: SQL query with %s placeholders
            params: Tuple of parameters for the query
            fetch: Whether to fetch results
            
        Returns:
            List of dictionaries (for SELECT) or None (for INSERT/UPDATE)
        """
        result = None
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, params or ())
                    
                    if fetch and cursor.description:
                        columns = [desc[0] for desc in cursor.description]
                        result = [dict(zip(columns, row)) for row in cursor.fetchall()]
                    elif not fetch:
                        conn.commit()
                        logger.info(f"Query affected {cursor.rowcount} rows")
                    
                    return result
                    
        except Error as e:
            logger.error(f"Query failed: {str(e)}")
            if hasattr(e, 'pgcode'):
                logger.error(f"PostgreSQL error code: {e.pgcode}")
            raise

# Example usage
if __name__ == "__main__":
    # Set environment variables (in production, use .env file or secrets manager)
    os.environ.update({
        'DB_HOST': 'localhost',
        'DB_PORT': '5432',
        'DB_NAME': 'mydatabase',
        'DB_USER': 'myuser',
        'DB_PASSWORD': 'mypassword'
    })
    
    try:
        db = SecurePostgresConnector()
        
        # Example parameterized query (safe from SQL injection)
        users = db.execute_query(
            "SELECT * FROM users WHERE email = %s AND status = %s;",
            ('user@example.com', 'active')
        )
        print(f"Found {len(users or [])} users")
        
        # Example INSERT with error handling
        try:
            db.execute_query(
                "INSERT INTO logs (message) VALUES (%s);",
                ('Security event occurred',),
                fetch=False
            )
        except Error as e:
            if hasattr(e, 'pgcode') and e.pgcode == '23505':
                print("Duplicate entry prevented")
            else:
                raise
        
    except Exception as e:
        logger.critical(f"Application error: {str(e)}")
        exit(1)