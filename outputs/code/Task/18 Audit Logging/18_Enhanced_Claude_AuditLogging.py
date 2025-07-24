"""
Secure Audit Logging System
A comprehensive audit logging solution with security best practices
"""

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, asdict
import secrets
import gzip
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class AuditLevel(Enum):
    """Audit event severity levels"""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    SECURITY = "SECURITY"


class AuditAction(Enum):
    """Common audit actions"""
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    ACCESS = "ACCESS"
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    ADMIN = "ADMIN"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    DATA_EXPORT = "DATA_EXPORT"
    SYSTEM_START = "SYSTEM_START"
    SYSTEM_STOP = "SYSTEM_STOP"


@dataclass
class AuditEvent:
    """Audit event data structure"""
    timestamp: str
    level: AuditLevel
    action: AuditAction
    user_id: str
    session_id: str
    source_ip: str
    resource: str
    details: Dict[str, Any]
    request_id: Optional[str] = None
    user_agent: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['level'] = self.level.value
        data['action'] = self.action.value
        return data


class SecurityValidator:
    """Input validation and sanitization"""
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """Sanitize string input"""
        if not isinstance(value, str):
            raise ValueError("Input must be a string")
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in value if ord(char) >= 32 or char in '\t\n\r')
        
        # Truncate to max length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "..."
        
        return sanitized
    
    @staticmethod
    def validate_user_id(user_id: str) -> str:
        """Validate and sanitize user ID"""
        if not user_id or len(user_id) > 255:
            raise ValueError("Invalid user ID")
        return SecurityValidator.sanitize_string(user_id, 255)
    
    @staticmethod
    def validate_ip_address(ip: str) -> str:
        """Basic IP address validation"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            return "INVALID_IP"


class CryptoManager:
    """Handles encryption and integrity verification"""
    
    def __init__(self, password: str):
        """Initialize with encryption password"""
        self.salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.cipher = Fernet(key)
        
        # HMAC key for integrity
        self.hmac_key = os.urandom(32)
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt data"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()
    
    def generate_integrity_hash(self, data: str) -> str:
        """Generate HMAC for data integrity"""
        return hmac.new(
            self.hmac_key,
            data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def verify_integrity(self, data: str, expected_hash: str) -> bool:
        """Verify data integrity"""
        computed_hash = self.generate_integrity_hash(data)
        return hmac.compare_digest(computed_hash, expected_hash)


class SecureAuditLogger:
    """Main secure audit logging class"""
    
    def __init__(self, 
                 db_path: str = "audit.db",
                 encryption_password: Optional[str] = None,
                 max_log_size: int = 100 * 1024 * 1024,  # 100MB
                 retention_days: int = 365):
        """
        Initialize secure audit logger
        
        Args:
            db_path: Path to SQLite database
            encryption_password: Password for encrypting sensitive data
            max_log_size: Maximum log file size before rotation
            retention_days: Number of days to retain logs
        """
        self.db_path = Path(db_path)
        self.max_log_size = max_log_size
        self.retention_days = retention_days
        self.lock = threading.Lock()
        
        # Initialize crypto if password provided
        self.crypto = CryptoManager(encryption_password) if encryption_password else None
        
        # Setup database
        self._init_database()
        
        # Setup file logging as backup
        self._setup_file_logging()
        
        # Validator instance
        self.validator = SecurityValidator()
        
        # Log system startup
        self.log_event(
            level=AuditLevel.INFO,
            action=AuditAction.SYSTEM_START,
            user_id="SYSTEM",
            session_id="",
            source_ip="127.0.0.1",
            resource="audit_logger",
            details={"message": "Audit logging system started"}
        )
    
    def _init_database(self):
        """Initialize SQLite database with security considerations"""
        with sqlite3.connect(self.db_path) as conn:
            # Enable WAL mode for better concurrency
            conn.execute("PRAGMA journal_mode=WAL")
            
            # Create audit table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    action TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    session_id TEXT,
                    source_ip TEXT,
                    resource TEXT,
                    details TEXT,
                    request_id TEXT,
                    user_agent TEXT,
                    integrity_hash TEXT,
                    encrypted BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON audit_events(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_action ON audit_events(action)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_level ON audit_events(level)")
            
            conn.commit()
    
    def _setup_file_logging(self):
        """Setup file-based logging as backup"""
        log_dir = Path("audit_logs")
        log_dir.mkdir(exist_ok=True)
        
        self.file_logger = logging.getLogger("audit_file")
        self.file_logger.setLevel(logging.INFO)
        
        # Rotating file handler
        from logging.handlers import RotatingFileHandler
        handler = RotatingFileHandler(
            log_dir / "audit.log",
            maxBytes=self.max_log_size,
            backupCount=10
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S UTC'
        )
        handler.setFormatter(formatter)
        self.file_logger.addHandler(handler)
    
    def log_event(self,
                  level: AuditLevel,
                  action: AuditAction,
                  user_id: str,
                  session_id: str,
                  source_ip: str,
                  resource: str,
                  details: Dict[str, Any],
                  request_id: Optional[str] = None,
                  user_agent: Optional[str] = None) -> bool:
        """
        Log an audit event securely
        
        Returns:
            bool: True if logged successfully, False otherwise
        """
        try:
            with self.lock:
                # Validate inputs
                user_id = self.validator.validate_user_id(user_id)
                source_ip = self.validator.validate_ip_address(source_ip)
                resource = self.validator.sanitize_string(resource)
                
                # Create audit event
                event = AuditEvent(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    level=level,
                    action=action,
                    user_id=user_id,
                    session_id=session_id,
                    source_ip=source_ip,
                    resource=resource,
                    details=details,
                    request_id=request_id,
                    user_agent=user_agent
                )
                
                # Serialize event data
                event_json = json.dumps(event.to_dict(), sort_keys=True)
                
                # Generate integrity hash
                integrity_hash = self._generate_event_hash(event_json)
                
                # Encrypt sensitive data if crypto enabled
                encrypted = False
                if self.crypto and level == AuditLevel.SECURITY:
                    event_json = self.crypto.encrypt_data(event_json)
                    encrypted = True
                
                # Store in database
                self._store_event_db(event, event_json, integrity_hash, encrypted)
                
                # Also log to file
                self._store_event_file(event)
                
                # Clean old logs periodically
                if secrets.randbelow(100) == 0:  # 1% chance
                    self._cleanup_old_logs()
                
                return True
                
        except Exception as e:
            # Log error to file logger
            self.file_logger.error(f"Failed to log audit event: {str(e)}")
            return False
    
    def _generate_event_hash(self, event_data: str) -> str:
        """Generate hash for event integrity"""
        if self.crypto:
            return self.crypto.generate_integrity_hash(event_data)
        else:
            return hashlib.sha256(event_data.encode()).hexdigest()
    
    def _store_event_db(self, event: AuditEvent, event_json: str, 
                       integrity_hash: str, encrypted: bool):
        """Store event in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO audit_events 
                (timestamp, level, action, user_id, session_id, source_ip, 
                 resource, details, request_id, user_agent, integrity_hash, encrypted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp,
                event.level.value,
                event.action.value,
                event.user_id,
                event.session_id,
                event.source_ip,
                event.resource,
                event_json,
                event.request_id,
                event.user_agent,
                integrity_hash,
                encrypted
            ))
            conn.commit()
    
    def _store_event_file(self, event: AuditEvent):
        """Store event in file log"""
        log_message = f"{event.level.value} - {event.action.value} - {event.user_id} - {event.resource}"
        self.file_logger.info(log_message)
    
    def query_events(self, 
                    start_time: Optional[str] = None,
                    end_time: Optional[str] = None,
                    user_id: Optional[str] = None,
                    action: Optional[AuditAction] = None,
                    level: Optional[AuditLevel] = None,
                    limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Query audit events with filters
        
        Args:
            start_time: Start time in ISO format
            end_time: End time in ISO format
            user_id: Filter by user ID
            action: Filter by action
            level: Filter by level
            limit: Maximum number of results
            
        Returns:
            List of audit events
        """
        try:
            query = "SELECT * FROM audit_events WHERE 1=1"
            params = []
            
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)
            
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)
            
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            
            if action:
                query += " AND action = ?"
                params.append(action.value)
            
            if level:
                query += " AND level = ?"
                params.append(level.value)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)
                
                events = []
                for row in cursor.fetchall():
                    event_dict = dict(row)
                    
                    # Decrypt if necessary
                    if event_dict['encrypted'] and self.crypto:
                        try:
                            event_dict['details'] = self.crypto.decrypt_data(event_dict['details'])
                        except Exception:
                            event_dict['details'] = "DECRYPTION_FAILED"
                    
                    events.append(event_dict)
                
                return events
                
        except Exception as e:
            self.file_logger.error(f"Failed to query events: {str(e)}")
            return []
    
    def verify_integrity(self, event_id: int) -> bool:
        """Verify integrity of a specific audit event"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT details, integrity_hash, encrypted FROM audit_events WHERE id = ?",
                    (event_id,)
                )
                row = cursor.fetchone()
                
                if not row:
                    return False
                
                details, stored_hash, encrypted = row
                
                if encrypted and self.crypto:
                    # For encrypted data, we can't verify without decrypting
                    try:
                        decrypted = self.crypto.decrypt_data(details)
                        return self.crypto.verify_integrity(decrypted, stored_hash)
                    except Exception:
                        return False
                else:
                    # Verify non-encrypted data
                    computed_hash = self._generate_event_hash(details)
                    return hmac.compare_digest(computed_hash, stored_hash)
                    
        except Exception as e:
            self.file_logger.error(f"Failed to verify integrity: {str(e)}")
            return False
    
    def _cleanup_old_logs(self):
        """Clean up old audit logs based on retention policy"""
        try:
            cutoff_date = datetime.now(timezone.utc).replace(
                day=datetime.now().day - self.retention_days
            ).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "DELETE FROM audit_events WHERE timestamp < ?",
                    (cutoff_date,)
                )
                deleted_count = cursor.rowcount
                conn.commit()
                
                if deleted_count > 0:
                    self.file_logger.info(f"Cleaned up {deleted_count} old audit records")
                    
        except Exception as e:
            self.file_logger.error(f"Failed to cleanup old logs: {str(e)}")
    
    def export_logs(self, output_path: str, 
                   start_time: Optional[str] = None,
                   end_time: Optional[str] = None) -> bool:
        """
        Export audit logs to a file
        
        Args:
            output_path: Path for export file
            start_time: Start time filter
            end_time: End time filter
            
        Returns:
            bool: Success status
        """
        try:
            events = self.query_events(
                start_time=start_time,
                end_time=end_time,
                limit=10000
            )
            
            # Log the export action
            self.log_event(
                level=AuditLevel.INFO,
                action=AuditAction.DATA_EXPORT,
                user_id="SYSTEM",
                session_id="",
                source_ip="127.0.0.1",
                resource="audit_logs",
                details={
                    "export_path": output_path,
                    "record_count": len(events),
                    "start_time": start_time,
                    "end_time": end_time
                }
            )
            
            # Export to compressed JSON
            with gzip.open(output_path, 'wt', encoding='utf-8') as f:
                json.dump(events, f, indent=2, default=str)
            
            return True
            
        except Exception as e:
            self.file_logger.error(f"Failed to export logs: {str(e)}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get audit log statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                stats = {}
                
                # Total events
                cursor = conn.execute("SELECT COUNT(*) FROM audit_events")
                stats['total_events'] = cursor.fetchone()[0]
                
                # Events by level
                cursor = conn.execute("""
                    SELECT level, COUNT(*) 
                    FROM audit_events 
                    GROUP BY level
                """)
                stats['events_by_level'] = dict(cursor.fetchall())
                
                # Events by action
                cursor = conn.execute("""
                    SELECT action, COUNT(*) 
                    FROM audit_events 
                    GROUP BY action 
                    ORDER BY COUNT(*) DESC 
                    LIMIT 10
                """)
                stats['top_actions'] = dict(cursor.fetchall())
                
                # Recent activity
                cursor = conn.execute("""
                    SELECT COUNT(*) 
                    FROM audit_events 
                    WHERE timestamp > datetime('now', '-24 hours')
                """)
                stats['events_last_24h'] = cursor.fetchone()[0]
                
                return stats
                
        except Exception as e:
            self.file_logger.error(f"Failed to get statistics: {str(e)}")
            return {}
    
    def close(self):
        """Clean shutdown of audit logger"""
        self.log_event(
            level=AuditLevel.INFO,
            action=AuditAction.SYSTEM_STOP,
            user_id="SYSTEM",
            session_id="",
            source_ip="127.0.0.1",
            resource="audit_logger",
            details={"message": "Audit logging system stopped"}
        )


# Example usage and testing
if __name__ == "__main__":
    # Initialize secure audit logger
    logger = SecureAuditLogger(
        db_path="secure_audit.db",
        encryption_password="your_secure_password_here",
        retention_days=90
    )
    
    # Example audit events
    session_id = secrets.token_hex(16)
    
    # Login event
    logger.log_event(
        level=AuditLevel.SECURITY,
        action=AuditAction.LOGIN,
        user_id="john.doe",
        session_id=session_id,
        source_ip="192.168.1.100",
        resource="web_application",
        details={
            "login_method": "password",
            "success": True,
            "user_agent": "Mozilla/5.0..."
        },
        request_id="req_123456"
    )
    
    # Data access event
    logger.log_event(
        level=AuditLevel.INFO,
        action=AuditAction.ACCESS,
        user_id="john.doe",
        session_id=session_id,
        source_ip="192.168.1.100",
        resource="customer_database",
        details={
            "table": "customers",
            "records_accessed": 5,
            "query_type": "SELECT"
        }
    )
    
    # Administrative action
    logger.log_event(
        level=AuditLevel.WARNING,
        action=AuditAction.PERMISSION_CHANGE,
        user_id="admin",
        session_id=secrets.token_hex(16),
        source_ip="192.168.1.5",
        resource="user_management",
        details={
            "target_user": "jane.smith",
            "permission_changed": "database_read",
            "old_value": False,
            "new_value": True
        }
    )
    
    # Query recent events
    print("Recent audit events:")
    events = logger.query_events(limit=5)
    for event in events:
        print(f"- {event['timestamp']} | {event['level']} | {event['action']} | {event['user_id']}")
    
    # Get statistics
    print("\nAudit statistics:")
    stats = logger.get_statistics()
    for key, value in stats.items():
        print(f"- {key}: {value}")
    
    # Export logs
    logger.export_logs("audit_export.json.gz")
    print("\nLogs exported to audit_export.json.gz")
    
    # Clean shutdown
    logger.close()
