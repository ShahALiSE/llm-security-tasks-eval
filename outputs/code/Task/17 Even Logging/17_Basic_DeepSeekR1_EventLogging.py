import logging
from logging.handlers import RotatingFileHandler
import json
from datetime import datetime
import sys
import os

class EventLogger:
    """
    A comprehensive event logging system with multiple log levels and file rotation.
    """
    
    def __init__(self, name='event_logger', log_file='events.log', max_size=5*1024*1024, backup_count=5):
        """
        Initialize the logger.
        
        Args:
            name (str): Name of the logger
            log_file (str): Path to the log file
            max_size (int): Maximum size of log file before rotation (in bytes)
            backup_count (int): Number of backup logs to keep
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)  # Capture all levels by default
        
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(module)s - %(message)s'
        )
        
        # Add rotating file handler
        file_handler = RotatingFileHandler(
            log_file, maxBytes=max_size, backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Add console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Store additional context
        self.context = {}
    
    def add_context(self, **kwargs):
        """
        Add contextual information to be included in all subsequent log entries.
        """
        self.context.update(kwargs)
    
    def clear_context(self):
        """
        Clear all contextual information.
        """
        self.context = {}
    
    def _prepare_message(self, message, extra=None):
        """
        Prepare the log message with context and additional data.
        """
        log_data = {
            'message': message,
            'timestamp': datetime.utcnow().isoformat(),
            'context': self.context.copy()
        }
        
        if extra:
            log_data['extra'] = extra
            
        return json.dumps(log_data)
    
    def debug(self, message, extra=None):
        """
        Log a debug level message.
        """
        self.logger.debug(self._prepare_message(message, extra))
    
    def info(self, message, extra=None):
        """
        Log an info level message.
        """
        self.logger.info(self._prepare_message(message, extra))
    
    def warning(self, message, extra=None):
        """
        Log a warning level message.
        """
        self.logger.warning(self._prepare_message(message, extra))
    
    def error(self, message, extra=None):
        """
        Log an error level message.
        """
        self.logger.error(self._prepare_message(message, extra))
    
    def critical(self, message, extra=None):
        """
        Log a critical level message.
        """
        self.logger.critical(self._prepare_message(message, extra))
    
    def exception(self, message, extra=None):
        """
        Log an exception with stack trace.
        """
        self.logger.exception(self._prepare_message(message, extra))


# Example usage
if __name__ == "__main__":
    # Initialize logger
    logger = EventLogger(log_file='logs/application.log')
    
    # Add some context that will appear in all subsequent logs
    logger.add_context(application="MyApp", version="1.0.0")
    
    # Log messages at different levels
    logger.debug("This is a debug message", extra={"debug_info": "some debug data"})
    logger.info("Application started")
    
    try:
        # Simulate an operation that might fail
        result = 10 / 0
    except Exception as e:
        logger.error("Division by zero error occurred", extra={"operation": "division"})
        logger.exception("Exception details")
    
    logger.warning("This is a warning message")
    logger.critical("This is a critical message!")
    
    # Log with additional context
    logger.add_context(user_id="12345")
    logger.info("User logged in")
    
    # Clear context
    logger.clear_context()
    logger.info("Context cleared")