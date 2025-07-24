import logging
import logging.handlers
import hashlib
import hmac
import os
from datetime import datetime, timezone

class SecureEventLogger:
    def __init__(self, log_file_path, secret_key=None, max_log_size=1048576, backup_count=5):
        """
        Initialize secure event logger.
        
        Args:
            log_file_path (str): Path to the log file
            secret_key (bytes, optional): Secret key for HMAC integrity checking. If None, won't use HMAC.
            max_log_size (int): Maximum log file size in bytes before rotation (default: 1MB)
            backup_count (int): Number of backup logs to keep (default: 5)
        """
        self.log_file_path = log_file_path
        self.secret_key = secret_key
        
        # Create logger
        self.logger = logging.getLogger('SecureEventLogger')
        self.logger.setLevel(logging.INFO)
        
        # Create file handler with rotation
        handler = logging.handlers.RotatingFileHandler(
            log_file_path,
            maxBytes=max_log_size,
            backupCount=backup_count
        )
        
        # Set formatter with UTC timestamps
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S %Z'
        )
        formatter.converter = time.gmtime  # Use UTC time
        handler.setFormatter(formatter)
        
        # Add handler to logger
        self.logger.addHandler(handler)
        
        # Set permissions on log file (read/write for owner only)
        if os.path.exists(log_file_path):
            os.chmod(log_file_path, 0o600)
    
    def _generate_hmac(self, message):
        """Generate HMAC for message integrity verification."""
        if not self.secret_key:
            return None
        return hmac.new(self.secret_key, message.encode('utf-8'), hashlib.sha256).hexdigest()
    
    def log_event(self, level, event_type, description, user=None, ip_address=None, additional_data=None):
        """
        Log a secure event with integrity checking.
        
        Args:
            level (str): Log level (INFO, WARNING, ERROR, CRITICAL)
            event_type (str): Type of event (e.g., "AUTH_SUCCESS", "CONFIG_CHANGE")
            description (str): Description of the event
            user (str, optional): User associated with the event
            ip_address (str, optional): IP address associated with the event
            additional_data (dict, optional): Additional structured data
        """
        try:
            # Sanitize inputs
            level = str(level).upper()
            event_type = str(event_type).strip()
            description = str(description).strip()
            user = str(user).strip() if user else "anonymous"
            ip_address = str(ip_address).strip() if ip_address else "unknown"
            
            # Create log entry
            log_entry = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'level': level,
                'event_type': event_type,
                'description': description,
                'user': user,
                'ip_address': ip_address,
                'additional_data': additional_data or {}
            }
            
            # Convert to string representation
            log_str = str(log_entry)
            
            # Generate HMAC if secret key is provided
            if self.secret_key:
                hmac_value = self._generate_hmac(log_str)
                log_entry['integrity_check'] = hmac_value
                log_str = str(log_entry)
            
            # Log according to level
            if level == 'INFO':
                self.logger.info(log_str)
            elif level == 'WARNING':
                self.logger.warning(log_str)
            elif level == 'ERROR':
                self.logger.error(log_str)
            elif level == 'CRITICAL':
                self.logger.critical(log_str)
            else:
                self.logger.info(log_str)  # Default to INFO for unknown levels
                
        except Exception as e:
            # Fallback logging if something goes wrong
            self.logger.error(f"Failed to log event: {str(e)}", exc_info=True)
    
    def verify_log_integrity(self, log_entry):
        """
        Verify the integrity of a log entry using HMAC.
        
        Args:
            log_entry (str/dict): The log entry to verify
            
        Returns:
            bool: True if integrity is verified or no HMAC is used, False otherwise
        """
        if not self.secret_key:
            return True
            
        try:
            if isinstance(log_entry, str):
                import ast
                log_dict = ast.literal_eval(log_entry)
            else:
                log_dict = log_entry.copy()
            
            stored_hmac = log_dict.pop('integrity_check', None)
            if not stored_hmac:
                return False
                
            log_str = str(log_dict)
            calculated_hmac = self._generate_hmac(log_str)
            
            return hmac.compare_digest(stored_hmac, calculated_hmac)
            
        except Exception:
            return False


# Example usage
if __name__ == "__main__":
    # Generate a secret key (in production, load from secure configuration)
    secret_key = os.urandom(32)  # 256-bit key
    
    # Initialize logger
    logger = SecureEventLogger(
        log_file_path='/var/log/secure_app_events.log',
        secret_key=secret_key
    )
    
    # Log some events
    logger.log_event(
        level='INFO',
        event_type='AUTH_SUCCESS',
        description='User logged in successfully',
        user='admin',
        ip_address='192.168.1.100'
    )
    
    logger.log_event(
        level='WARNING',
        event_type='AUTH_FAILURE',
        description='Invalid login attempt',
        user='attacker',
        ip_address='10.0.0.5'
    )