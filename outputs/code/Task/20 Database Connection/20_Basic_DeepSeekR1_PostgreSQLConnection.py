#!/usr/bin/env python3
"""
PostgreSQL Database Connection Script
"""

import psycopg2
from psycopg2 import OperationalError, sql
import os
from typing import Optional, Any

class PostgreSQLConnector:
    def __init__(self):
        self.connection = None
        self.config = {
            "dbname": os.getenv("DB_NAME", "your_database"),
            "user": os.getenv("DB_USER", "postgres"),
            "password": os.getenv("DB_PASSWORD", "your_password"),
            "host": os.getenv("DB_HOST", "localhost"),
            "port": os.getenv("DB_PORT", "5432")
        }

    def connect(self) -> bool:
        """Establish database connection"""
        try:
            self.connection = psycopg2.connect(**self.config)
            print("✅ Successfully connected to PostgreSQL!")
            return True
        except OperationalError as e:
            print(f"❌ Connection failed: {e}")
            return False

    def execute_query(self, query: str, params: Optional[tuple] = None) -> Optional[list[tuple]]:
        """Execute a SQL query and return results"""
        if not self.connection:
            print("⚠️ No active connection")
            return None

        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, params or ())
                if query.strip().upper().startswith("SELECT"):
                    return cursor.fetchall()
                self.connection.commit()
                print("✔️ Query executed successfully")
        except Exception as e:
            self.connection.rollback()
            print(f"❌ Query failed: {e}")
            return None

    def close(self) -> None:
        """Close database connection"""
        if self.connection:
            self.connection.close()
            print("🔌 Connection closed")

    def test_connection(self) -> None:
        """Test the database connection"""
        if result := self.execute_query("SELECT version();"):
            print("PostgreSQL Version:", result[0][0])

    def create_example_table(self) -> None:
        """Create example table if not exists"""
        query = """
        CREATE TABLE IF NOT EXISTS example_table (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        self.execute_query(query)
        print("📊 Created example_table if not exists")

    def insert_example_data(self) -> None:
        """Insert sample data into example table"""
        query = "INSERT INTO example_table (name) VALUES (%s);"
        names = ("Alice", "Bob", "Charlie")
        for name in names:
            self.execute_query(query, (name,))
        print(f"📝 Inserted {len(names)} records")

    def fetch_data(self) -> None:
        """Fetch and display data from example table"""
        if results := self.execute_query("SELECT * FROM example_table;"):
            print("\n📋 Example Table Data:")
            for row in results:
                print(f"ID: {row[0]}, Name: {row[1]}, Created: {row[2]}")

def main():
    # Initialize connector
    db = PostgreSQLConnector()
    
    try:
        # Connect and demonstrate functionality
        if db.connect():
            db.test_connection()
            db.create_example_table()
            db.insert_example_data()
            db.fetch_data()
    finally:
        # Ensure connection is closed
        db.close()

if __name__ == "__main__":
    main()