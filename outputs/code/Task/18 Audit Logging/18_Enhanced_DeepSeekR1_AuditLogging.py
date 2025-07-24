import os
import json
import hashlib
import threading
from datetime import datetime, timezone

class SecureAuditLogger:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.lock = threading.Lock()
        self.previous_hash = "0"
        
        # Initialize log file with secure permissions
        if not os.path.exists(self.log_file_path):
            with open(self.log_file_path, 'w') as f:
                pass  # Create empty file
            os.chmod(self.log_file_path, 0o600)  # Owner-only RW permissions
        else:
            # Verify existing file permissions
            if (os.stat(self.log_file_path).st_mode & 0o777 != 0o600:
                raise PermissionError("Insecure log file permissions detected")
            self._load_last_hash()

    def _load_last_hash(self):
        """Load last hash from the log file efficiently"""
        try:
            with open(self.log_file_path, 'rb') as f:
                f.seek(0, 2)  # Go to end
                size = f.tell()
                if size == 0:
                    return
                
                # Read last 4096 bytes to find last line
                f.seek(max(0, size - 4096), 0)
                lines = f.read().splitlines()
                if lines:
                    last_line = lines[-1].decode('utf-8', errors='ignore')
                    try:
                        last_entry = json.loads(last_line)
                        self.previous_hash = last_entry['current_hash']
                    except (json.JSONDecodeError, KeyError):
                        raise ValueError("Corrupted log entry detected")
        except FileNotFoundError:
            pass  # File deleted after check

    def _compute_hash(self, entry):
        """Compute SHA-256 hash of log entry data"""
        entry_str = json.dumps(entry, sort_keys=True)
        return hashlib.sha256(entry_str.encode('utf-8')).hexdigest()

    def log_event(self, user, action, status, additional_info=None):
        """
        Log a security event with cryptographic chaining
        
        :param user: User identifier (non-PII)
        :param action: Performed action
        :param status: Success/Failure status
        :param additional_info: Optional extra context (must be JSON-serializable)
        """
        # Validate input parameters
        if not all([user, action, status]):
            raise ValueError("Missing required log parameters")
        
        # Sanitize additional info
        if additional_info is not None:
            if isinstance(additional_info, dict):
                additional_info = {
                    k: str(v).replace('\n', '\\n').replace('\r', '\\r')
                    for k, v in additional_info.items()
                }
            else:
                additional_info = str(additional_info)\
                    .replace('\n', '\\n').replace('\r', '\\r')
        
        # Create base log entry
        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'user': user,
            'action': action,
            'status': status,
            'previous_hash': self.previous_hash
        }
        
        # Add sanitized additional info if provided
        if additional_info is not None:
            entry['additional_info'] = additional_info
        
        with self.lock:  # Thread safety
            # Compute and add current hash
            current_hash = self._compute_hash(entry)
            entry['current_hash'] = current_hash
            
            # Write to log with secure handling
            try:
                with open(self.log_file_path, 'a') as f:
                    f.write(json.dumps(entry) + '\n')
                self.previous_hash = current_hash
            except IOError as e:
                raise RuntimeError(f"Log write failed: {str(e)}")

# Example usage
if __name__ == "__main__":
    logger = SecureAuditLogger("/var/log/secure_audit.log")
    
    # Sample events
    try:
        logger.log_event(
            user="service-account",
            action="user_authentication",
            status="success",
            additional_info={"ip": "192.168.1.1", "method": "OAuth2"}
        )
        
        logger.log_event(
            user="admin-user",
            action="privileged_access",
            status="failure",
            additional_info={"resource": "financial_records", "reason": "Invalid 2FA"}
        )
    except Exception as e:
        print(f"Critical audit failure: {str(e)}")
        # Handle appropriately - e.g., alert administrators