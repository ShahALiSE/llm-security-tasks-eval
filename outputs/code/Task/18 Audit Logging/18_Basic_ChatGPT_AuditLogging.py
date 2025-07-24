import logging
from datetime import datetime

# Configure the audit logger
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)

# Create a file handler for the audit log
file_handler = logging.FileHandler('audit.log')
file_handler.setLevel(logging.INFO)

# Define the log format
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add the handler to the logger
audit_logger.addHandler(file_handler)

# Example functions that perform auditable actions
def log_user_login(username):
    audit_logger.info(f"User '{username}' logged in.")

def log_file_access(username, filename):
    audit_logger.info(f"User '{username}' accessed file '{filename}'.")

def log_config_change(username, config_name, old_value, new_value):
    audit_logger.info(f"User '{username}' changed '{config_name}' from '{old_value}' to '{new_value}'.")

# Example usage
if __name__ == "__main__":
    log_user_login("alice")
    log_file_access("alice", "report.pdf")
    log_config_change("alice", "max_users", 10, 20)
