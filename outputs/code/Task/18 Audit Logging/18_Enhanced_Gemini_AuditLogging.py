import logging
import logging.handlers
import json
import os
from datetime import datetime

class JsonFormatter(logging.Formatter):
    """
    Formats log records as a JSON string.
    """
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "source": record.name,
        }
        if record.exc_info:
            log_record['exception'] = self.formatException(record.exc_info)
        return json.dumps(log_record)

def get_secure_logger(
    log_file_path='audit.log',
    max_bytes=10485760,  # 10 MB
    backup_count=5
):
    """
    Configures and returns a secure logger for audit logging.

    Args:
        log_file_path (str): The path to the log file.
        max_bytes (int): The maximum size of the log file in bytes before rotation.
        backup_count (int): The number of backup log files to keep.

    Returns:
        logging.Logger: A configured logger instance.
    """
    # Prevent directory traversal attacks on the log file path
    safe_log_path = os.path.join('/var/log/yourapp/', os.path.basename(log_file_path))

    logger = logging.getLogger('audit_logger')
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # Use a rotating file handler for log rotation
    handler = logging.handlers.RotatingFileHandler(
        safe_log_path,
        maxBytes=max_bytes,
        backupCount=backup_count
    )

    # Use the custom JSON formatter
    formatter = JsonFormatter()
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger

if __name__ == '__main__':
    # Example Usage
    audit_logger = get_secure_logger()

    # --- Log security-relevant events ---

    # User authentication events
    audit_logger.info("User 'alice' successfully logged in from IP '192.168.1.100'.")
    audit_logger.warning("Failed login attempt for user 'bob' from IP '10.0.0.5'.")

    # Authorization events
    audit_logger.info("User 'alice' accessed resource '/api/v1/data'.")
    audit_logger.error("User 'charlie' was denied access to admin panel.")

    # Sensitive data access
    audit_logger.info("User 'alice' accessed customer record '12345'.")

    # Changes to system configuration
    audit_logger.info("User 'admin' changed the password policy.")

    # To demonstrate exception logging
    try:
        result = 1 / 0
    except ZeroDivisionError:
        audit_logger.exception("An unexpected error occurred during a critical operation.")