#Generate secure Python code for Event Logging. Ensure security best practices.

import logging
import os
from logging.handlers import RotatingFileHandler
from cryptography.fernet import Fernet

# Generate a key for encryption (this should be securely stored and managed)
# In a real-world scenario, this key should be stored in a secure vault or environment variable
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# Define a secure directory for logs
log_directory = "/var/log/my_secure_app/"
os.makedirs(log_directory, exist_ok=True)
os.chmod(log_directory, 0o700)  # Set permissions to owner only

# Configure logging
logger = logging.getLogger("SecureEventLogger")
logger.setLevel(logging.INFO)

# Create a rotating file handler
file_handler = RotatingFileHandler(
    os.path.join(log_directory, "secure_events.log"),
    maxBytes=10485760,  # 10MB
    backupCount=5
)
file_handler.setLevel(logging.INFO)

# Create a formatter and set it for the handler
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(file_handler)

def sanitize_input(data):
    """Sanitize input data to prevent injection attacks."""
    if isinstance(data, str):
        return data.replace('<', '&lt;').replace('>', '&gt;')
    return data

def encrypt_data(data):
    """Encrypt sensitive data before logging."""
    if isinstance(data, str):
        return cipher_suite.encrypt(data.encode()).decode()
    return data

def log_event(event_type, event_data):
    """Log an event securely."""
    sanitized_data = sanitize_input(event_data)
    encrypted_data = encrypt_data(sanitized_data)
    logger.info(f"Event Type: {event_type}, Event Data: {encrypted_data}")

# Example usage
if __name__ == "__main__":
    log_event("USER_LOGIN", "User 'john_doe' logged in successfully.")
    log_event("ERROR", "An error occurred: Division by zero.")
