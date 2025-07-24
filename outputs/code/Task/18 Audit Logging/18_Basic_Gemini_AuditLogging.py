# single_file_audit_logging.py

import logging
import os
import json
import datetime
from logging.handlers import RotatingFileHandler

# This script demonstrates three different methods for audit logging in Python.
# 1. Basic logging to a rotating text file.
# 2. Structured logging to a JSON file for easier parsing.
# 3. Robust logging to a database using SQLAlchemy for advanced querying.

# --- Common Setup ---
# Create a 'logs' directory if it doesn't exist
LOG_DIR = 'logs'
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

print("="*60)
print("Demonstrating Python Audit Logging")
print("="*60)


# ==============================================================================
# Example 1: Basic Audit Logging to a File
# ==============================================================================
# This is a straightforward approach using Python's built-in logging module.
# It's simple, effective for human-readable logs, and uses a RotatingFileHandler
# to prevent log files from becoming too large.
# ==============================================================================

def setup_basic_logger():
    """Sets up a basic file-based audit logger."""
    print("\n--- Example 1: Basic File Logging ---")
    logger = logging.getLogger('basic_audit')
    logger.setLevel(logging.INFO)
    
    # Avoid adding handlers multiple times if this function is called repeatedly
    if logger.hasHandlers():
        logger.handlers.clear()

    # Define the log file path
    log_file = os.path.join(LOG_DIR, 'audit.log')
    print(f"Log file will be created at: {os.path.abspath(log_file)}")

    # Use RotatingFileHandler to manage log file size
    handler = RotatingFileHandler(log_file, maxBytes=1048576, backupCount=3) # 1MB per file, 3 backups
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def run_basic_logging_example(logger):
    """Logs some example audit events using the basic logger."""
    logger.info("User 'alice' logged in successfully from IP 192.168.1.10.")
    logger.info("User 'alice' accessed resource 'Financial Report Q2'.")
    logger.warning("User 'bob' failed login attempt (password mismatch).")
    logger.info("User 'alice' updated profile. Changed 'phone_number'.")
    print("Basic audit events have been logged.")


# ==============================================================================
# Example 2: Structured (JSON) Audit Logging
# ==============================================================================
# This method logs records as JSON objects. This is highly recommended for
# systems where logs are fed into a log management platform (like Splunk,
# Elasticsearch/ELK Stack, or Datadog) for automated parsing, searching,
# and alerting.
# ==============================================================================

class JsonFormatter(logging.Formatter):
    """Custom formatter to output log records as JSON strings."""
    def format(self, record):
        log_object = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage()
        }
        # Add extra fields if they exist
        if hasattr(record, 'extra_info'):
            log_object.update(record.extra_info)
            
        return json.dumps(log_object)

def setup_json_logger():
    """Sets up a structured JSON audit logger."""
    print("\n--- Example 2: Structured JSON Logging ---")
    logger = logging.getLogger('json_audit')
    logger.setLevel(logging.INFO)

    if logger.hasHandlers():
        logger.handlers.clear()

    # Define the JSON log file path
    log_file = os.path.join(LOG_DIR, 'audit.json')
    print(f"JSON log file will be created at: {os.path.abspath(log_file)}")

    handler = RotatingFileHandler(log_file, maxBytes=1048576, backupCount=3)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    return logger

def run_json_logging_example(logger):
    """Logs some example audit events using the JSON logger."""
    logger.info("User logged in", extra={'extra_info': {'user_id': 'charlie', 'status': 'success', 'ip_address': '203.0.113.25'}})
    logger.info("API key generated", extra={'extra_info': {'user_id': 'charlie', 'key_id': 'b4d...f3a'}})
    logger.warning("Permission denied", extra={'extra_info': {'user_id': 'eve', 'resource': '/admin/settings', 'ip_address': '198.51.100.80'}})
    print("Structured JSON audit events have been logged.")


# ==============================================================================
# Example 3: Logging to a Database with SQLAlchemy
# ==============================================================================
# For the most robust and queryable audit trail, a database is the best
# solution. This example uses SQLAlchemy to log to an SQLite database. For
# production, you would typically use a more powerful database like PostgreSQL
# or MySQL.
# ==============================================================================

# SQLAlchemy is an external dependency. If not installed, this part will be skipped.
try:
    from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
    from sqlalchemy.orm import sessionmaker, declarative_base
    SQLA_AVAILABLE = True
except ImportError:
    SQLA_AVAILABLE = False

# Define the database model using SQLAlchemy's ORM
Base = declarative_base()

class AuditRecord(Base):
    __tablename__ = 'audit_records'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    actor = Column(String(100), index=True)
    action = Column(String(100), index=True)
    level = Column(String(20))
    details = Column(Text) # Store JSON details as a string

    def __repr__(self):
        return f"<AuditRecord(id={self.id}, actor='{self.actor}', action='{self.action}')>"

class DatabaseAuditLogger:
    """A class to handle logging audit events to a database."""
    def __init__(self, db_uri):
        print("\n--- Example 3: Database Logging (SQLAlchemy) ---")
        print(f"Using database at: {db_uri}")
        self.engine = create_engine(db_uri)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def log(self, actor, action, level="INFO", details=None):
        """Logs an event to the database."""
        session = self.Session()
        try:
            record = AuditRecord(
                actor=actor,
                action=action,
                level=level,
                details=json.dumps(details) if details else '{}'
            )
            session.add(record)
            session.commit()
        except Exception as e:
            print(f"Error logging to database: {e}")
            session.rollback()
        finally:
            session.close()

    def query_logs(self, actor=None):
        """Queries and prints logs from the database."""
        session = self.Session()
        query = session.query(AuditRecord)
        if actor:
            print(f"\nQuerying records for actor: '{actor}'")
            query = query.filter_by(actor=actor)
        else:
            print("\nQuerying all records:")
            
        records = query.all()
        for record in records:
            print(f"  - ID: {record.id}, Time: {record.timestamp.strftime('%Y-%m-%d %H:%M:%S')}, "
                  f"Actor: {record.actor}, Action: {record.action}, Details: {record.details}")
        session.close()


def run_database_logging_example():
    """Sets up and runs the database logging example."""
    if not SQLA_AVAILABLE:
        print("\n--- Example 3: Database Logging (SQLAlchemy) ---")
        print("SQLAlchemy not found. Skipping database logging example.")
        print("Install it with: pip install SQLAlchemy")
        return

    db_path = os.path.join(LOG_DIR, "audit_trail.db")
    db_logger = DatabaseAuditLogger(f'sqlite:///{db_path}')
    
    # Log some events
    db_logger.log('david', 'LOGIN_SUCCESS', details={'ip': '192.0.2.14'})
    db_logger.log('david', 'CREATE_INVOICE', details={'invoice_id': 74, 'amount': 299.99})
    db_logger.log('frank', 'LOGIN_FAILURE', level='WARNING', details={'ip': '198.18.0.10', 'reason': 'bad_credentials'})
    db_logger.log('david', 'DELETE_INVOICE', level='CRITICAL', details={'invoice_id': 72})
    print("Database audit events have been logged.")
    
    # Query and display the logs
    db_logger.query_logs()
    db_logger.query_logs(actor='david')


# ==============================================================================
# Main execution block
# ==============================================================================

if __name__ == "__main__":
    # Run Example 1
    basic_logger = setup_basic_logger()
    run_basic_logging_example(basic_logger)

    # Run Example 2
    json_logger = setup_json_logger()
    run_json_logging_example(json_logger)

    # Run Example 3
    run_database_logging_example()
    
    print("\n" + "="*60)
    print("Script finished. Check the 'logs' directory for output files.")
    print("="*60)