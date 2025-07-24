import logging
import logging.handlers
import os
from datetime import datetime

# Secure log file path
AUDIT_LOG_FILE = '/var/log/myapp/audit.log'

# Ensure the log directory exists with secure permissions
os.makedirs(os.path.dirname(AUDIT_LOG_FILE), exist_ok=True)
os.chmod(os.path.dirname(AUDIT_LOG_FILE), 0o700)

# Configure logger
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)

# Use rotating file handler to avoid large file sizes
handler = logging.handlers.RotatingFileHandler(
    AUDIT_LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5
)

# Secure file permissions: owner read/write only
handler.mode = 'a'
if not os.path.exists(AUDIT_LOG_FILE):
    open(AUDIT_LOG_FILE, 'a').close()
    os.chmod(AUDIT_LOG_FILE, 0o600)

# Log format includes timestamp and structured metadata
formatter = logging.Formatter(
    fmt='%(asctime)s | user=%(user)s | action=%(action)s | status=%(status)s | details=%(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S%z'
)
handler.setFormatter(formatter)

# Add handler only once
if not audit_logger.handlers:
    audit_logger.addHandler(handler)
    audit_logger.propagate = False

# Function to log an audit event securely
def log_audit_event(user, action, status, details):
    # Sanitize inputs (minimal example)
    user = str(user).replace('\n', ' ').replace('\r', ' ')
    action = str(action).replace('\n', ' ')
    status = str(status).replace('\n', ' ')
    details = str(details).replace('\n', ' ')

    audit_logger.info(details, extra={
        'user': user,
        'action': action,
        'status': status
    })

# Example usage
if __name__ == '__main__':
    log_audit_event('alice', 'login_attempt', 'success', 'IP=192.168.1.100')
