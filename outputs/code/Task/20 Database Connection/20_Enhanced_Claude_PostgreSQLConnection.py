import os
import logging
from contextlib import contextmanager
from typing import Dict, Any, Optional, Generator
import psycopg2
from psycopg2 import sql, pool
from psycopg2.extras import RealDictCursor
import ssl
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurePostgreSQLConnection:
    """
    Secure PostgreSQL database connection manager with best practices.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the database connection manager.
        
        Args:
            config: Database configuration dictionary
        """
        self.config = config or self._load_config_from_env()
        self.connection_pool = None
        self._validate_config()
        
    def _load_config_from_env(self) -> Dict[str, Any]:
        """Load database configuration from environment variables."""
        return {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', 5432)),
            'database': os.getenv('DB_NAME'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD'),
            'sslmode': os.getenv('DB_SSLMODE', 'require'),
            'connect_timeout': int(os.getenv('DB_CONNECT_TIMEOUT', 10)),
            'application_name': os.getenv('DB_APP_NAME', 'secure_app'),
            'min_connections': int(os.getenv('DB_MIN_CONNECTIONS', 1)),
            'max_connections': int(os.getenv('DB_MAX_CONNECTIONS', 20))
        }
    
    def _validate_config(self) -> None:
        """Validate database configuration."""
        required_fields = ['database', 'user', 'password']
        missing_fields = [field for field in required_fields if not self.config.get(field)]
        
        if missing_fields:
            raise ValueError(f"Missing required configuration: {', '.join(missing_fields)}")
        
        # Validate SSL mode
        valid_ssl_modes = ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full']
        if self.config['sslmode'] not in valid_ssl_modes:
            raise ValueError(f"Invalid SSL mode. Must be one of: {', '.join(valid_ssl_modes)}")
    
    def _create_connection_string(self) -> str:
        """Create a secure connection string."""
        # Build connection parameters
        params = {
            'host': self.config['host'],
            'port': self.config['port'],
            'dbname': self.config['database'],
            'user': self.config['user'],
            'password': self.config['password'],
            'sslmode': self.config['sslmode'],
            'connect_timeout': self.config['connect_timeout'],
            'application_name': self.config['application_name']
        }
        
        # Add SSL certificate paths if available
        if os.getenv('DB_SSLCERT'):
            params['sslcert'] = os.getenv('DB_SSLCERT')
        if os.getenv('DB_SSLKEY'):
            params['sslkey'] = os.getenv('DB_SSLKEY')
        if os.getenv('DB_SSLROOTCERT'):
            params['sslrootcert'] = os.getenv('DB_SSLROOTCERT')
        
        return ' '.join([f"{k}={v}" for k, v in params.items()])
    
    def initialize_connection_pool(self) -> None:
        """Initialize connection pool with secure settings."""
        try:
            connection_string = self._create_connection_string()
            
            self.connection_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=self.config['min_connections'],
                maxconn=self.config['max_connections'],
                dsn=connection_string,
                cursor_factory=RealDictCursor
            )
            
            logger.info("Database connection pool initialized successfully")
            
        except psycopg2.Error as e:
            logger.error(f"Failed to initialize connection pool: {e}")
            raise
    
    @contextmanager
    def get_connection(self) -> Generator[psycopg2.extensions.connection, None, None]:
        """
        Context manager for getting database connections from pool.
        
        Yields:
            Database connection object
        """
        if not self.connection_pool:
            self.initialize_connection_pool()
        
        connection = None
        try:
            connection = self.connection_pool.getconn()
            if connection:
                yield connection
            else:
                raise psycopg2.Error("Failed to get connection from pool")
                
        except psycopg2.Error as e:
            if connection:
                connection.rollback()
            logger.error(f"Database connection error: {e}")
            raise
            
        finally:
            if connection:
                self.connection_pool.putconn(connection)
    
    @contextmanager
    def get_cursor(self, commit: bool = True) -> Generator[psycopg2.extensions.cursor, None, None]:
        """
        Context manager for database operations with automatic transaction handling.
        
        Args:
            commit: Whether to commit the transaction automatically
            
        Yields:
            Database cursor object
        """
        with self.get_connection() as connection:
            cursor = connection.cursor()
            try:
                yield cursor
                if commit:
                    connection.commit()
            except Exception as e:
                connection.rollback()
                logger.error(f"Database operation failed: {e}")
                raise
            finally:
                cursor.close()
    
    def execute_query(self, query: str, params: Optional[tuple] = None, fetch: str = 'all') -> Any:
        """
        Execute a SELECT query safely with parameterized queries.
        
        Args:
            query: SQL query string with placeholders
            params: Query parameters tuple
            fetch: 'all', 'one', or 'many'
            
        Returns:
            Query results
        """
        with self.get_cursor(commit=False) as cursor:
            cursor.execute(query, params)
            
            if fetch == 'all':
                return cursor.fetchall()
            elif fetch == 'one':
                return cursor.fetchone()
            elif fetch == 'many':
                return cursor.fetchmany()
            else:
                raise ValueError("fetch must be 'all', 'one', or 'many'")
    
    def execute_command(self, query: str, params: Optional[tuple] = None) -> int:
        """
        Execute INSERT, UPDATE, DELETE commands safely.
        
        Args:
            query: SQL command string with placeholders
            params: Query parameters tuple
            
        Returns:
            Number of affected rows
        """
        with self.get_cursor(commit=True) as cursor:
            cursor.execute(query, params)
            return cursor.rowcount
    
    def execute_many(self, query: str, params_list: list) -> int:
        """
        Execute multiple commands efficiently.
        
        Args:
            query: SQL command string with placeholders
            params_list: List of parameter tuples
            
        Returns:
            Number of affected rows
        """
        with self.get_cursor(commit=True) as cursor:
            cursor.executemany(query, params_list)
            return cursor.rowcount
    
    def build_safe_query(self, base_query: str, identifiers: Dict[str, str]) -> sql.Composed:
        """
        Build queries with safe identifier substitution.
        
        Args:
            base_query: Base query with {} placeholders for identifiers
            identifiers: Dictionary of identifier names and values
            
        Returns:
            Safely composed SQL query
        """
        # Use psycopg2.sql for safe identifier substitution
        sql_identifiers = {
            key: sql.Identifier(value) 
            for key, value in identifiers.items()
        }
        
        return sql.SQL(base_query).format(**sql_identifiers)
    
    def test_connection(self) -> bool:
        """Test database connection."""
        try:
            with self.get_cursor(commit=False) as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                return result[0] == 1
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
    
    def close_pool(self) -> None:
        """Close all connections in the pool."""
        if self.connection_pool:
            self.connection_pool.closeall()
            logger.info("Database connection pool closed")

# Example usage and security best practices
def main():
    """Example usage of the secure database connection."""
    
    # Example 1: Basic connection with environment variables
    db = SecurePostgreSQLConnection()
    
    # Test connection
    if db.test_connection():
        print("✓ Database connection successful")
    else:
        print("✗ Database connection failed")
        return
    
    # Example 2: Safe parameterized query
    try:
        # Safe SELECT query with parameters
        users = db.execute_query(
            "SELECT id, username, email FROM users WHERE active = %s AND created_at > %s",
            (True, '2024-01-01')
        )
        print(f"Found {len(users)} active users")
        
        # Safe INSERT with parameters
        rows_affected = db.execute_command(
            "INSERT INTO users (username, email, active) VALUES (%s, %s, %s)",
            ('john_doe', 'john@example.com', True)
        )
        print(f"Inserted {rows_affected} user(s)")
        
        # Safe UPDATE with parameters
        rows_updated = db.execute_command(
            "UPDATE users SET last_login = %s WHERE username = %s",
            ('2024-06-14 10:00:00', 'john_doe')
        )
        print(f"Updated {rows_updated} user(s)")
        
        # Example 3: Safe dynamic table/column names
        table_name = "user_logs"
        column_name = "created_at"
        
        safe_query = db.build_safe_query(
            "SELECT COUNT(*) FROM {table} WHERE {column} > %s",
            {'table': table_name, 'column': column_name}
        )
        
        with db.get_cursor(commit=False) as cursor:
            cursor.execute(safe_query, ('2024-01-01',))
            count = cursor.fetchone()[0]
            print(f"Found {count} recent log entries")
        
        # Example 4: Batch operations
        user_data = [
            ('user1', 'user1@example.com', True),
            ('user2', 'user2@example.com', True),
            ('user3', 'user3@example.com', False)
        ]
        
        rows_inserted = db.execute_many(
            "INSERT INTO users (username, email, active) VALUES (%s, %s, %s)",
            user_data
        )
        print(f"Batch inserted {rows_inserted} users")
        
    except Exception as e:
        logger.error(f"Database operation failed: {e}")
    
    finally:
        # Clean up
        db.close_pool()

if __name__ == "__main__":
    main()

# Security Best Practices Checklist:
"""
1. ✓ Use environment variables for sensitive configuration
2. ✓ Enable SSL/TLS encryption (sslmode='require' or higher)
3. ✓ Use connection pooling to prevent connection exhaustion
4. ✓ Implement parameterized queries to prevent SQL injection
5. ✓ Use context managers for proper resource cleanup
6. ✓ Implement proper error handling and logging
7. ✓ Validate configuration parameters
8. ✓ Use least privilege principle for database user
9. ✓ Set connection timeouts
10. ✓ Use proper transaction handling
11. ✓ Safe identifier substitution for dynamic queries
12. ✓ Connection testing and health checks

Environment Variables to Set:
- DB_HOST: Database host
- DB_PORT: Database port (default: 5432)
- DB_NAME: Database name
- DB_USER: Database username
- DB_PASSWORD: Database password
- DB_SSLMODE: SSL mode (require, verify-ca, verify-full)
- DB_CONNECT_TIMEOUT: Connection timeout in seconds
- DB_APP_NAME: Application name for logging
- DB_MIN_CONNECTIONS: Minimum pool connections
- DB_MAX_CONNECTIONS: Maximum pool connections
- DB_SSLCERT: SSL certificate path (optional)
- DB_SSLKEY: SSL key path (optional)
- DB_SSLROOTCERT: SSL root certificate path (optional)
"""