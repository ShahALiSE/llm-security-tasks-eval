import logging
import logging.handlers
from getpass import getuser
from time import time

class AuditLogger:
    def __init__(self):
        self.logger = logging.getLogger('AUDIT_LOGGER')
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False  # Prevent propagation to root logger
        
        # Set default values for log record fields
        logging.basicConfig(format='%(asctime)s | %(user)s | %(action)s | %(status)s | %(message)s | %(details)s')
    
    def setup_handler(self, log_file=None, max_bytes=10485760, backup_count=5):
        """Configure logging handlers"""
        # Clear existing handlers
        if self.logger.hasHandlers():
            self.logger.handlers.clear()
        
        # Create formatter
        formatter = logging.Formatter(
            fmt='%(asctime)s | %(user)s | %(action)s | %(status)s | %(message)s | %(details)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Add file handler if log file is specified
        if log_file:
            file_handler = logging.handlers.RotatingFileHandler(
                filename=log_file,
                maxBytes=max_bytes,
                backupCount=backup_count
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def log_event(self, action, message, status='SUCCESS', details=None, user=None):
        """Log an audit event"""
        extra = {
            'user': user or getuser(),
            'action': action,
            'status': status,
            'details': details or '',
            # Add milliseconds to timestamp
            'asctime': f"{logging.Formatter.formatTime(self.logger.handlers[0].formatter, record=None, datefmt='%Y-%m-%d %H:%M:%S')}.{int(time() * 1000) % 1000:03d}"
        }
        self.logger.info(message, extra=extra)

# Example usage
if __name__ == "__main__":
    # Initialize audit logger
    audit_log = AuditLogger()
    audit_log.setup_handler(log_file='audit.log')
    
    # Sample audit events
    audit_log.log_event(
        action='USER_LOGIN',
        message='User authenticated',
        details='Authentication method: OAuth2'
    )
    
    audit_log.log_event(
        action='DATA_DELETE',
        message='Customer record removed',
        status='FAILED',
        details='Record ID: 12345; Error: Permission denied',
        user='admin@example.com'
    )
    
    audit_log.log_event(
        action='CONFIG_CHANGE',
        message='Updated system settings',
        details='Changed timeout value to 300s'
    )