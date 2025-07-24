"""
SQL Injection Prevention using Parameterized Queries
====================================================

This module demonstrates secure database operations using parameterized queries
to prevent SQL injection attacks across different Python database libraries.
"""

import sqlite3
import mysql.connector
import psycopg2
from typing import List, Dict, Any, Optional


class SecureDatabase:
    """Base class demonstrating secure database operations."""
    
    def __init__(self, connection):
        self.connection = connection
        self.cursor = connection.cursor()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection:
            self.connection.close()


class SQLiteSecure(SecureDatabase):
    """Secure SQLite operations using parameterized queries."""
    
    @classmethod
    def connect(cls, database_path: str):
        """Create a secure SQLite connection."""
        conn = sqlite3.connect(database_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access
        return cls(conn)
    
    def create_users_table(self):
        """Create users table with proper schema."""
        query = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
        self.cursor.execute(query)
        self.connection.commit()
    
    def insert_user(self, username: str, email: str, password_hash: str) -> int:
        """Safely insert a new user using parameterized query."""
        query = """
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        """
        try:
            self.cursor.execute(query, (username, email, password_hash))
            self.connection.commit()
            return self.cursor.lastrowid
        except sqlite3.IntegrityError as e:
            raise ValueError(f"User creation failed: {e}")
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Safely retrieve user by username."""
        query = "SELECT * FROM users WHERE username = ?"
        self.cursor.execute(query, (username,))
        row = self.cursor.fetchone()
        return dict(row) if row else None
    
    def get_users_by_criteria(self, **criteria) -> List[Dict]:
        """Safely search users with multiple criteria."""
        if not criteria:
            return []
        
        # Build WHERE clause dynamically but safely
        conditions = []
        values = []
        
        for field, value in criteria.items():
            # Whitelist allowed fields to prevent column injection
            allowed_fields = ['username', 'email', 'id']
            if field not in allowed_fields:
                raise ValueError(f"Invalid field: {field}")
            
            conditions.append(f"{field} = ?")
            values.append(value)
        
        query = f"SELECT * FROM users WHERE {' AND '.join(conditions)}"
        self.cursor.execute(query, values)
        return [dict(row) for row in self.cursor.fetchall()]
    
    def update_user_email(self, user_id: int, new_email: str) -> bool:
        """Safely update user email."""
        query = "UPDATE users SET email = ? WHERE id = ?"
        self.cursor.execute(query, (new_email, user_id))
        self.connection.commit()
        return self.cursor.rowcount > 0
    
    def delete_user(self, user_id: int) -> bool:
        """Safely delete user by ID."""
        query = "DELETE FROM users WHERE id = ?"
        self.cursor.execute(query, (user_id,))
        self.connection.commit()
        return self.cursor.rowcount > 0
    
    def search_users_like(self, username_pattern: str) -> List[Dict]:
        """Safely search users with LIKE pattern."""
        query = "SELECT * FROM users WHERE username LIKE ?"
        # The pattern should be prepared by the caller (e.g., f"%{term}%")
        self.cursor.execute(query, (username_pattern,))
        return [dict(row) for row in self.cursor.fetchall()]


class MySQLSecure(SecureDatabase):
    """Secure MySQL operations using parameterized queries."""
    
    @classmethod
    def connect(cls, host: str, user: str, password: str, database: str):
        """Create a secure MySQL connection."""
        conn = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database,
            autocommit=False
        )
        return cls(conn)
    
    def insert_user(self, username: str, email: str, password_hash: str) -> int:
        """Safely insert user using MySQL parameterized query."""
        query = """
        INSERT INTO users (username, email, password_hash)
        VALUES (%s, %s, %s)
        """
        try:
            self.cursor.execute(query, (username, email, password_hash))
            self.connection.commit()
            return self.cursor.lastrowid
        except mysql.connector.IntegrityError as e:
            raise ValueError(f"User creation failed: {e}")
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Safely retrieve user by email."""
        query = "SELECT * FROM users WHERE email = %s"
        self.cursor.execute(query, (email,))
        row = self.cursor.fetchone()
        if row:
            columns = [desc[0] for desc in self.cursor.description]
            return dict(zip(columns, row))
        return None
    
    def bulk_insert_users(self, users_data: List[tuple]) -> int:
        """Safely insert multiple users using executemany."""
        query = """
        INSERT INTO users (username, email, password_hash)
        VALUES (%s, %s, %s)
        """
        try:
            self.cursor.executemany(query, users_data)
            self.connection.commit()
            return self.cursor.rowcount
        except mysql.connector.IntegrityError as e:
            self.connection.rollback()
            raise ValueError(f"Bulk insert failed: {e}")


class PostgreSQLSecure(SecureDatabase):
    """Secure PostgreSQL operations using parameterized queries."""
    
    @classmethod
    def connect(cls, host: str, database: str, user: str, password: str):
        """Create a secure PostgreSQL connection."""
        conn = psycopg2.connect(
            host=host,
            database=database,
            user=user,
            password=password
        )
        conn.autocommit = False
        return cls(conn)
    
    def insert_user_returning(self, username: str, email: str, password_hash: str) -> Dict:
        """Insert user and return the created record."""
        query = """
        INSERT INTO users (username, email, password_hash)
        VALUES (%s, %s, %s)
        RETURNING id, username, email, created_at
        """
        try:
            self.cursor.execute(query, (username, email, password_hash))
            self.connection.commit()
            row = self.cursor.fetchone()
            columns = [desc[0] for desc in self.cursor.description]
            return dict(zip(columns, row))
        except psycopg2.IntegrityError as e:
            self.connection.rollback()
            raise ValueError(f"User creation failed: {e}")
    
    def get_users_paginated(self, offset: int = 0, limit: int = 10) -> List[Dict]:
        """Safely retrieve paginated users."""
        query = """
        SELECT id, username, email, created_at
        FROM users
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
        """
        self.cursor.execute(query, (limit, offset))
        rows = self.cursor.fetchall()
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in rows]


# Vulnerable vs Secure Examples
class VulnerableExamples:
    """Examples of VULNERABLE code - DO NOT USE IN PRODUCTION!"""
    
    @staticmethod
    def vulnerable_login(connection, username: str, password: str):
        """VULNERABLE: Direct string concatenation - susceptible to SQL injection."""
        cursor = connection.cursor()
        # This is DANGEROUS - never do this!
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        return cursor.fetchone()
    
    @staticmethod
    def vulnerable_search(connection, search_term: str):
        """VULNERABLE: String formatting - susceptible to SQL injection."""
        cursor = connection.cursor()
        # This is DANGEROUS - never do this!
        query = "SELECT * FROM users WHERE username LIKE '%" + search_term + "%'"
        cursor.execute(query)
        return cursor.fetchall()


class SecureExamples:
    """Examples of SECURE code using parameterized queries."""
    
    @staticmethod
    def secure_login(connection, username: str, password_hash: str):
        """SECURE: Using parameterized queries."""
        cursor = connection.cursor()
        query = "SELECT * FROM users WHERE username = ? AND password_hash = ?"
        cursor.execute(query, (username, password_hash))
        return cursor.fetchone()
    
    @staticmethod
    def secure_search(connection, search_term: str):
        """SECURE: Using parameterized queries with LIKE."""
        cursor = connection.cursor()
        query = "SELECT * FROM users WHERE username LIKE ?"
        # Prepare the pattern safely
        pattern = f"%{search_term}%"
        cursor.execute(query, (pattern,))
        return cursor.fetchall()


# Input Validation and Sanitization
class InputValidator:
    """Additional input validation for defense in depth."""
    
    @staticmethod
    def validate_username(username: str) -> str:
        """Validate and sanitize username input."""
        if not username or len(username.strip()) < 3:
            raise ValueError("Username must be at least 3 characters")
        
        if len(username) > 50:
            raise ValueError("Username must be less than 50 characters")
        
        # Allow only alphanumeric characters and underscores
        import re
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            raise ValueError("Username can only contain letters, numbers, and underscores")
        
        return username.strip().lower()
    
    @staticmethod
    def validate_email(email: str) -> str:
        """Validate email format."""
        import re
        email = email.strip().lower()
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(pattern, email):
            raise ValueError("Invalid email format")
        
        if len(email) > 254:
            raise ValueError("Email too long")
        
        return email


# Usage Examples
def demo_secure_operations():
    """Demonstrate secure database operations."""
    
    # SQLite example
    with SQLiteSecure.connect(':memory:') as db:
        # Create table
        db.create_users_table()
        
        # Validate and insert user
        try:
            username = InputValidator.validate_username("john_doe")
            email = InputValidator.validate_email("john@example.com")
            password_hash = "hashed_password_here"  # Use proper hashing like bcrypt
            
            user_id = db.insert_user(username, email, password_hash)
            print(f"Created user with ID: {user_id}")
            
            # Retrieve user safely
            user = db.get_user_by_username("john_doe")
            print(f"Retrieved user: {user}")
            
            # Search with criteria
            users = db.get_users_by_criteria(username="john_doe")
            print(f"Search results: {users}")
            
            # Pattern search
            pattern_users = db.search_users_like("%john%")
            print(f"Pattern search: {pattern_users}")
            
        except ValueError as e:
            print(f"Validation error: {e}")


# Security Best Practices Summary
"""
SQL Injection Prevention Best Practices:

1. ALWAYS use parameterized queries/prepared statements
   - SQLite: Use ? placeholders
   - MySQL: Use %s placeholders
   - PostgreSQL: Use %s placeholders

2. NEVER concatenate user input directly into SQL strings
   - Avoid: f"SELECT * FROM users WHERE id = {user_id}"
   - Use: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

3. Validate and sanitize all user inputs
   - Check data types, lengths, and formats
   - Use whitelisting for allowed characters
   - Implement business logic validation

4. Use stored procedures when possible
   - Pre-compiled SQL reduces injection risk
   - Centralized business logic

5. Apply principle of least privilege
   - Database users should have minimal necessary permissions
   - Use separate accounts for different operations

6. Enable SQL query logging and monitoring
   - Monitor for suspicious query patterns
   - Set up alerts for potential injection attempts

7. Keep database software updated
   - Apply security patches promptly
   - Follow vendor security recommendations

8. Use ORM frameworks carefully
   - Even ORMs can be vulnerable if used incorrectly
   - Understand how your ORM handles raw queries
"""

if __name__ == "__main__":
    demo_secure_operations()
