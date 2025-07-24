import logging
import logging.handlers
import os
import json
import hashlib
import hmac
import time
import socket
import uuid
from datetime import datetime
from pathlib import Path
import secrets
from typing import Dict, Any, Optional, Union

class SecureEventLogger:
    """A secure logging system implementing security best practices."""
    
    def __init__(self, 
                 log_file_path: str = "logs/events.log", 
                 log_level: int = logging.INFO,
                 max_log_size: int = 10 * 1024 * 1024,  # 10 MB
                 backup_count: int = 5,
                 hmac_key: Optional[bytes] = None):
        """
        Initialize the secure logger with proper configurations.
        
        Args:
            log_file_path: Path where log files will be stored
            log_level: Logging level (INFO, WARNING, ERROR, etc.)
            max_log_size: Maximum size in bytes before log rotation
            backup_count: Number of backup logs to keep
            hmac_key: Secret key for HMAC verification (generated if None)
        """
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(log_file_path)
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        
        # Generate HMAC key if not provided
        self.hmac_key = hmac_key if hmac_key else secrets.token_bytes(32)
        
        # Configure logger with rotation
        self.logger = logging.getLogger('secure_event_logger')
        self.logger.setLevel(log_level)
        
        # Remove any existing handlers to avoid duplicates
        if self.logger.handlers:
            for handler in self.logger.handlers:
                self.logger.removeHandler(handler)
        
        # Set up a rotating file handler with proper permissions
        handler = logging.handlers.RotatingFileHandler(
            log_file_path,
            maxBytes=max_log_size,
            backupCount=backup_count
        )
        
        # Set file permissions to be restrictive
        os.chmod(log_file_path, 0o600)  # Owner read/write only
        
        # Use a formatter that includes all relevant security information
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
        
        # Track failed log attempts
        self.failed_log_attempts = 0
        self.hostname = socket.gethostname()

    def _generate_event_id(self) -> str:
        """Generate a unique ID for each log event."""
        return str(uuid.uuid4())
    
    def _create_hmac(self, message: str) -> str:
        """Create an HMAC for the message to ensure integrity."""
        return hmac.new(
            self.hmac_key, 
            message.encode('utf-8'), 
            hashlib.sha256
        ).hexdigest()
    
    def log_event(self, 
                  event_type: str, 
                  data: Dict[str, Any], 
                  security_level: str = "normal",
                  source: Optional[str] = None) -> bool:
        """
        Log an event securely with integrity verification.
        
        Args:
            event_type: Type of event being logged
            data: Event data to be logged
            security_level: Importance of the security event
            source: Source of the event
            
        Returns:
            bool: Success status of the logging operation
        """
        try:
            # Sanitize inputs
            event_type = self._sanitize_input(event_type)
            security_level = self._sanitize_input(security_level)
            source = self._sanitize_input(source if source else "application")
            
            # Construct the event
            timestamp = datetime.utcnow().isoformat()
            event_id = self._generate_event_id()
            
            event = {
                "event_id": event_id,
                "timestamp": timestamp,
                "event_type": event_type,
                "security_level": security_level,
                "source": source,
                "hostname": self.hostname,
                "data": data
            }
            
            # Convert to JSON for consistent formatting
            event_json = json.dumps(event, default=str)
            
            # Generate HMAC for integrity
            signature = self._create_hmac(event_json)
            
            # Log with integrity signature
            log_entry = f"{event_json} | HMAC: {signature}"
            self.logger.info(log_entry)
            
            return True
        
        except Exception as e:
            self.failed_log_attempts += 1
            
            # If normal logging fails, try emergency logging
            try:
                error_msg = f"Failed to log event: {str(e)}"
                self.logger.error(error_msg)
            except:
                # Last resort: write to stderr
                print(f"CRITICAL: Event logging system failure: {str(e)}", 
                      file=os.sys.stderr)
            
            return False
    
    def _sanitize_input(self, input_str: Optional[str]) -> str:
        """Sanitize input to prevent log injection attacks."""
        if input_str is None:
            return ""
            
        # Remove control characters and sanitize newlines
        sanitized = ''.join(char for char in input_str if ord(char) >= 32 or char == '\n')
        sanitized = sanitized.replace('\n', '\\n')
        
        return sanitized
    
    def log_security_event(self, 
                          event_name: str, 
                          user_id: str, 
                          status: str,
                          details: Dict[str, Any]) -> bool:
        """
        Log security-specific events like authentication, authorization, etc.
        
        Args:
            event_name: Name of the security event
            user_id: ID of the user involved
            status: Outcome status (success/failure/etc)
            details: Additional details about the event
            
        Returns:
            bool: Success status of the logging operation
        """
        security_data = {
            "user_id": user_id,
            "status": status,
            "details": details,
            "ip_address": self._get_client_ip()
        }
        
        return self.log_event(
            event_type=f"SECURITY_{event_name.upper()}", 
            security_level="high",
            data=security_data
        )
    
    def _get_client_ip(self) -> str:
        """Placeholder for getting client IP - in a real app, extract from request context."""
        return "127.0.0.1"
    
    def validate_log_integrity(self, log_entry: str) -> bool:
        """
        Validate the integrity of a log entry using its HMAC.
        
        Args:
            log_entry: Complete log entry including HMAC
            
        Returns:
            bool: True if the log entry has not been tampered with
        """
        try:
            # Split the log entry and the HMAC
            parts = log_entry.split(" | HMAC: ")
            if len(parts) != 2:
                return False
            
            log_content, provided_hmac = parts
            
            # Calculate expected HMAC
            expected_hmac = self._create_hmac(log_content)
            
            # Compare in constant time to prevent timing attacks
            return hmac.compare_digest(provided_hmac, expected_hmac)
            
        except Exception:
            return False


# Example usage:
if __name__ == "__main__":
    # Create a secure logger
    secure_logger = SecureEventLogger()
    
    # Log a regular event
    secure_logger.log_event(
        event_type="USER_ACTION",
        data={
            "action": "file_download",
            "file_id": "doc-123456",
            "file_name": "sensitive_report.pdf"
        }
    )
    
    # Log a security-related event
    secure_logger.log_security_event(
        event_name="LOGIN_ATTEMPT",
        user_id="user@example.com",
        status="success",
        details={
            "method": "2FA",
            "device": "mobile",
            "browser": "Chrome 98.0.4758.102"
        }
    )
    
    print("Events logged successfully")
