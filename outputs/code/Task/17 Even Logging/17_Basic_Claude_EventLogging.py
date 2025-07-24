import logging
import datetime
import os
import json
from typing import Dict, Any, Optional


class EventLogger:
    """
    A flexible event logging system that can log events to console and/or files
    with customizable formatting and severity levels.
    """
    
    def __init__(
        self,
        name: str = "event_logger",
        log_to_console: bool = True,
        log_to_file: bool = True,
        log_file_path: str = "logs",
        log_level: int = logging.INFO,
        json_format: bool = False
    ):
        """
        Initialize the event logger.
        
        Args:
            name: Name of the logger
            log_to_console: Whether to log to console
            log_to_file: Whether to log to file
            log_file_path: Directory path for log files
            log_level: Minimum log level to record
            json_format: Whether to format logs as JSON
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        self.json_format = json_format
        
        # Clear any existing handlers
        if self.logger.hasHandlers():
            self.logger.handlers.clear()
        
        # Console handler
        if log_to_console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(log_level)
            
            if json_format:
                formatter = logging.Formatter('%(message)s')
            else:
                formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        # File handler
        if log_to_file:
            # Create log directory if it doesn't exist
            if not os.path.exists(log_file_path):
                os.makedirs(log_file_path)
            
            # Create log file with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = os.path.join(log_file_path, f"{name}_{timestamp}.log")
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            
            if json_format:
                formatter = logging.Formatter('%(message)s')
            else:
                formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def log_event(
        self,
        event_type: str,
        message: str,
        level: int = logging.INFO,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log an event with the specified type, message, level, and context.
        
        Args:
            event_type: Type of event (e.g., 'user_login', 'data_processing')
            message: Human-readable message describing the event
            level: Severity level of the event
            context: Additional contextual information as a dictionary
        """
        if context is None:
            context = {}
            
        event_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event_type": event_type,
            "message": message,
            "context": context
        }
        
        if self.json_format:
            log_message = json.dumps(event_data)
        else:
            log_message = f"Event: {event_type} - {message} - Context: {context}"
        
        self.logger.log(level, log_message)
    
    def info(self, event_type: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log an info-level event."""
        self.log_event(event_type, message, logging.INFO, context)
    
    def warning(self, event_type: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log a warning-level event."""
        self.log_event(event_type, message, logging.WARNING, context)
    
    def error(self, event_type: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log an error-level event."""
        self.log_event(event_type, message, logging.ERROR, context)
    
    def critical(self, event_type: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log a critical-level event."""
        self.log_event(event_type, message, logging.CRITICAL, context)
    
    def debug(self, event_type: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log a debug-level event."""
        self.log_event(event_type, message, logging.DEBUG, context)


# Example usage
if __name__ == "__main__":
    # Initialize logger with JSON formatting
    event_logger = EventLogger(
        name="app_events",
        log_to_console=True,
        log_to_file=True,
        log_file_path="logs",
        json_format=True
    )
    
    # Log different types of events
    event_logger.info(
        event_type="user_login",
        message="User successfully logged in",
        context={"user_id": "12345", "ip_address": "192.168.1.1"}
    )
    
    event_logger.warning(
        event_type="rate_limit",
        message="User approaching API rate limit",
        context={"user_id": "12345", "current_rate": "45/50"}
    )
    
    event_logger.error(
        event_type="database_error",
        message="Failed to connect to database",
        context={"db_host": "db.example.com", "error_code": "TIMEOUT"}
    )
    
    # Example of a more complex event with nested context
    event_logger.info(
        event_type="order_processed",
        message="Customer order has been processed successfully",
        context={
            "order_id": "ORD-9876",
            "customer": {
                "id": "CUST-1234",
                "name": "Jane Doe"
            },
            "items": [
                {"product_id": "PROD-001", "quantity": 2, "price": 19.99},
                {"product_id": "PROD-005", "quantity": 1, "price": 49.99}
            ],
            "total_amount": 89.97,
            "payment_method": "credit_card"
        }
    )
