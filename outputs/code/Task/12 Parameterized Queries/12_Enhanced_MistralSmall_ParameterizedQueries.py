 import sqlite3
import re
from typing import Optional, List, Dict, Any, Union

class SQLiteSecureManager:
    def __init__(self, db_path: str = 'secure_app.db'):
        """
        Initialize the SQLite database manager with security best practices.

        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self.connection = None
        self._initialize_secure_connection()

    def _initialize_secure_connection(self) -> None:
        """Establish a secure connection to the SQLite database with security enhancements."""
        try:
            # Connect to the database with isolation level SERIALIZABLE for maximum consistency
            self.connection = sqlite3.connect(
                self.db_path,
                isolation_level='SERIALIZABLE',
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
            )

            # Enable foreign key constraints
            self.connection.execute("PRAGMA foreign_keys = ON")

            # Set synchronous mode to FULL for maximum data integrity
            self.connection.execute("PRAGMA synchronous = FULL")

            # Enable secure delete (overwrite deleted content)
            self.connection.execute("PRAGMA secure_delete = ON")

            # Set temp store to memory for better performance with temporary tables
            self.connection.execute("PRAGMA temp_store = MEMORY")

        except sqlite3.Error as e:
            raise RuntimeError(f"Failed to initialize secure database connection: {str(e)}")

    def _validate_input(self, value: Any) -> bool:
        """
        Validate input to prevent SQL injection and other malicious inputs.

        Args:
            value: The input value to validate

        Returns:
            bool: True if input is valid, False otherwise
        """
        if value is None:
            return True

        if isinstance(value, str):
            # Check for SQL injection patterns
            sql_injection_patterns = [
                r'\b(ALTER|CREATE|DELETE|DROP|EXEC|INSERT|MERGE|SELECT|UPDATE|UNION)\b',
                r'(\-\-)|(;)|(/\*)|(\*/)|(xp_)|(shutdown)|(waitfor)',
                r'(\bOR\b|\bAND\b)[\s\S]*?=',
                r'\b(LOAD_FILE|INTO OUTFILE|INTO DUMPFILE)\b'
            ]

            for pattern in sql_injection_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    return False

            # Check for reasonable length
            if len(value) > 1000:  # Adjust based on your needs
                return False

        return True

    def _sanitize_input(self, value: Any) -> Union[str, Any]:
        """
        Sanitize input values to prevent potential issues.

        Args:
            value: The input value to sanitize

        Returns:
            Sanitized value
        """
        if isinstance(value, str):
            # Remove potentially harmful characters while preserving legitimate content
            return re.sub(r'[;\-\*\/\\]', '', value)
        return value

    def execute_query(
        self,
        query: str,
        parameters: Optional[Union[tuple, dict]] = None,
        fetch: bool = False,
        commit: bool = True
    ) -> Optional[List[Dict]]:
        """
        Execute a parameterized query with security protections.

        Args:
            query: The SQL query with placeholders
            parameters: Parameters for the query (tuple or dict)
            fetch: Whether to fetch results
            commit: Whether to commit the transaction

        Returns:
            List of dictionaries representing rows if fetch=True, None otherwise

        Raises:
            ValueError: If input validation fails
            sqlite3.Error: For database errors
        """
        if not self.connection:
            raise RuntimeError("Database connection not established")

        # Validate all parameters
        if parameters:
            if isinstance(parameters, dict):
                if not all(self._validate_input(v) for v in parameters.values()):
                    raise ValueError("Invalid input parameters detected")
            else:
                if not all(self._validate_input(v) for v in parameters):
                    raise ValueError("Invalid input parameters detected")

        try:
            with self.connection as conn:  # Automatically handles commit/rollback
                cursor = conn.cursor()

                # Use sanitized parameters
                sanitized_params = None
                if parameters:
                    if isinstance(parameters, dict):
                        sanitized_params = {k: self._sanitize_input(v) for k, v in parameters.items()}
                    else:
                        sanitized_params = tuple(self._sanitize_input(v) for v in parameters)

                # Execute the query
                if parameters and isinstance(parameters, dict):
                    cursor.execute(query, sanitized_params)
                else:
                    cursor.execute(query, sanitized_params or ())

                if fetch:
                    # Get column names and row data
                    columns = [column[0] for column in cursor.description]
                    rows = cursor.fetchall()
                    return [dict(zip(columns, row)) for row in rows]

                if commit and not fetch:
                    conn.commit()

                return None

        except sqlite3.IntegrityError as e:
            self.connection.rollback()
            raise ValueError(f"Database integrity error: {str(e)}")
        except sqlite3.Error as e:
            self.connection.rollback()
            raise RuntimeError(f"Database operation failed: {str(e)}")

    def create_secure_tables(self) -> None:
        """Create tables with security constraints and proper data types."""
        queries = [
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                login_attempts INTEGER NOT NULL DEFAULT 0,
                account_locked BOOLEAN NOT NULL DEFAULT 0,
                CONSTRAINT valid_email CHECK (email LIKE '%_@__%.__%')
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
            )
            """
        ]

        for query in queries:
            self.execute_query(query)

    def add_user(self, username: str, email: str, password_hash: str) -> int:
        """
        Securely add a new user with parameterized queries.

        Args:
            username: The username
            email: The email address
            password_hash: The hashed password

        Returns:
            The ID of the newly created user

        Raises:
            ValueError: If validation fails or user already exists
        """
        # Additional validation
        if not (username and email and password_hash):
            raise ValueError("Username, email, and password hash are required")

        if len(username) > 50:
            raise ValueError("Username too long")

        if len(email) > 100:
            raise ValueError("Email too long")

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValueError("Invalid email format")

        try:
            # Using named parameters for better readability and security
            query = """
            INSERT INTO users (username, email, password_hash)
            VALUES (:username, :email, :password_hash)
            """

            params = {
                'username': username,
                'email': email,
                'password_hash': password_hash
            }

            self.execute_query(query, params)
            return self.connection.execute("SELECT last_insert_rowid()").fetchone()[0]

        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed" in str(e):
                if "username" in str(e):
                    raise ValueError("Username already exists")
                elif "email" in str(e):
                    raise ValueError("Email already exists")
            raise

    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """
        Securely retrieve a user by ID using parameterized queries.

        Args:
            user_id: The user ID

        Returns:
            Dictionary representing the user if found, None otherwise
        """
        if not isinstance(user_id, int) or user_id <= 0:
            raise ValueError("Invalid user ID")

        query = "SELECT * FROM users WHERE user_id = ? AND is_active = 1"
        result = self.execute_query(query, (user_id,), fetch=True)
        return result[0] if result else None

    def update_user_email(self, user_id: int, new_email: str) -> bool:
        """
        Securely update a user's email address.

        Args:
            user_id: The user ID
            new_email: The new email address

        Returns:
            True if update was successful, False otherwise

        Raises:
            ValueError: If validation fails
        """
        if not isinstance(user_id, int) or user_id <= 0:
            raise ValueError("Invalid user ID")

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', new_email):
            raise ValueError("Invalid email format")

        if len(new_email) > 100:
            raise ValueError("Email too long")

        try:
            query = """
            UPDATE users
            SET email = ?,
                last_login = CURRENT_TIMESTAMP
            WHERE user_id = ?
            """
            self.execute_query(query, (new_email, user_id))
            return True
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed" in str(e):
                raise ValueError("Email already exists")
            raise

    def log_action(self, user_id: Optional[int], action: str, ip_address: str = '', user_agent: str = '') -> None:
        """
        Log user actions for security auditing.

        Args:
            user_id: The user ID or None for system actions
            action: Description of the action
            ip_address: IP address of the request
            user_agent: User agent string
        """
        if not action or len(action) > 200:
            raise ValueError("Invalid action")

        if ip_address and len(ip_address) > 45:
            raise ValueError("Invalid IP address")

        if user_agent and len(user_agent) > 200:
            raise ValueError("Invalid user agent")

        query = """
        INSERT INTO audit_log (user_id, action, ip_address, user_agent)
        VALUES (?, ?, ?, ?)
        """

        params = (user_id, action, ip_address[:45] if ip_address else None, user_agent[:200] if user_agent else None)
        self.execute_query(query, params, commit=True)

    def close(self) -> None:
        """Close the database connection securely."""
        if self.connection:
            try:
                # Run VACUUM to optimize the database before closing
                self.connection.execute("VACUUM")
                self.connection.close()
            except sqlite3.Error as e:
                print(f"Error closing database connection: {str(e)}")
            finally:
                self.connection = None

# Example usage
if __name__ == "__main__":
    try:
        # Initialize the secure database manager
        db = SQLiteSecureManager('secure_application.db')

        # Create secure tables
        db.create_secure_tables()

        # Example: Add a user
        try:
            user_id = db.add_user(
                username="secure_user",
                email="user@example.com",
                password_hash="hashed_password_123"  # In real app, use proper password hashing
            )
            print(f"Added user with ID: {user_id}")

            # Log the action
            db.log_action(user_id, "user_creation", "192.168.1.1", "Mozilla/5.0")
        except ValueError as e:
            print(f"Error adding user: {str(e)}")

        # Example: Get a user
        user = db.get_user_by_id(user_id)
        print(f"Retrieved user: {user}")

        # Example: Update user email
        try:
            db.update_user_email(user_id, "new.email@example.com")
            print("User email updated successfully")
        except ValueError as e:
            print(f"Error updating email: {str(e)}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        # Ensure the connection is closed properly
        if 'db' in locals():
            db.close()
