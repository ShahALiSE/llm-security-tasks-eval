import logging
import logging.handlers
import hashlib
import os
from datetime import datetime

def setup_logging(log_file='audit.log', max_bytes=1048576, backup_count=5):
    """
    Configure logging with rotation and secure handling.

    Args:
        log_file (str): Path to the log file.
        max_bytes (int): Maximum size of the log file before rotation.
        backup_count (int): Number of backup log files to keep.
    """
    # Create a logger
    logger = logging.getLogger('audit_logger')
    logger.setLevel(logging.INFO)

    # Create a file handler with rotation
    handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count
    )
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

    logger.addHandler(handler)
    return logger

def log_audit_event(logger, event, user, metadata=None):
    """
    Log an audit event securely.

    Args:
        logger (logging.Logger): The logger instance.
        event (str): The event to log.
        user (str): The user associated with the event.
        metadata (dict, optional): Additional metadata to log.
    """
    if metadata is None:
        metadata = {}

    # Ensure sensitive data is not logged
    if 'password' in metadata:
        metadata['password'] = '*****'
    if 'api_key' in metadata:
        metadata['api_key'] = '*****'

    # Create a log message
    log_message = f"Event: {event}, User: {user}, Metadata: {metadata}"

    # Log the event
    logger.info(log_message)

    # Calculate and log the hash of the log message for integrity checking
    log_hash = hashlib.sha256(log_message.encode()).hexdigest()
    logger.info(f"Hash: {log_hash}")

def main():
    # Setup logging
    logger = setup_logging()

    # Example audit event
    log_audit_event(logger, 'login', 'user123', {'ip_address': '192.168.1.1'})

if __name__ == '__main__':
    main()
