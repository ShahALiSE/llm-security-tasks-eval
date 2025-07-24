#Generate secure Python code for Event Logging. Ensure security best practices.

import logging
from logging.handlers import RotatingFileHandler
import os
import sys

def setup_secure_logger(
    name: str,
    log_file: str = "events.log",
    level: int = logging.INFO,
    max_bytes: int = 5 * 1024 * 1024,  # 5 MB
    backup_count: int = 3
) -> logging.Logger:
    """
    Set up a secure logger with rotation.
    
    Parameters:
    - name: The name of the logger.
    - log_file: File path for the log file.
    - level: Logging level.
    - max_bytes: Maximum size of each log file before rotation.
    - backup_count: Number of backup files to keep.

    Returns:
    - Configured Logger instance.
    """

    # Ensure the log directory exists with secure permissions
    log_dir = os.path.dirname(log_file) or "."
    os.makedirs(log_dir, exist_ok=True)

    # Set file permissions to owner read/write only
    if not os.path.exists(log_file):
        with open(log_file, 'a'):
            os.chmod(log_file, 0o600)  # -rw-------

    logger = logging.getLogger(name)
    logger.setLevel(level)

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Rotating File Handler
    file_handler = RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    # Console Handler (optional)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    # Avoid duplicate handlers
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    # Prevent propagation to the root logger
    logger.propagate = False

    return logger


# Example Usage
if __name__ == "__main__":
    logger = setup_secure_logger("MyAppLogger", "logs/app_events.log")

    # Example log event (Avoid logging sensitive data!)
    logger.info("Application started successfully.")
    logger.warning("Memory usage is high.")
    logger.error("Failed to connect to database.")
