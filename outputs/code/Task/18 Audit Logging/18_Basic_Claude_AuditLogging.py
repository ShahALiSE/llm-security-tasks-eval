import json
import logging
import datetime
from typing import Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass, asdict
import uuid
import hashlib
import os
from pathlib import Path


class AuditEventType(Enum):
    """Define different types of audit events"""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"
    SYSTEM_CONFIG_CHANGE = "system_config_change"
    PERMISSION_CHANGE = "permission_change"
    FAILED_AUTHENTICATION = "failed_authentication"
    API_ACCESS = "api_access"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"


class AuditSeverity(Enum):
    """Severity levels for audit events"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Data structure for audit events"""
    event_id: str
    timestamp: str
    event_type: AuditEventType
    severity: AuditSeverity
    user_id: Optional[str]
    user_ip: Optional[str]
    resource: Optional[str]
    action: str
    result: str  # success, failure, error
    details: Dict[str, Any]
    session_id: Optional[str] = None
    user_agent: Optional[str] = None
    checksum: Optional[str] = None


class AuditLogger:
    """Main audit logging class"""
    
    def __init__(self, 
                 log_file: str = "audit.log",
                 json_file: str = "audit.json",
                 enable_console: bool = False,
                 enable_integrity_check: bool = True):
        """
        Initialize the audit logger
        
        Args:
            log_file: Path to the text log file
            json_file: Path to the JSON log file
            enable_console: Whether to also log to console
            enable_integrity_check: Whether to add checksums for integrity
        """
        self.log_file = log_file
        self.json_file = json_file
        self.enable_console = enable_console
        self.enable_integrity_check = enable_integrity_check
        
        # Create directories if they don't exist
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        Path(json_file).parent.mkdir(parents=True, exist_ok=True)
        
        # Setup text logger
        self.logger = logging.getLogger('audit_logger')
        self.logger.setLevel(logging.INFO)
        
        # File handler for structured text logs
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Console handler (optional)
        if enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(file_formatter)
            self.logger.addHandler(console_handler)
    
    def _generate_checksum(self, event_data: str) -> str:
        """Generate SHA-256 checksum for integrity verification"""
        return hashlib.sha256(event_data.encode()).hexdigest()
    
    def _create_event(self,
                     event_type: AuditEventType,
                     action: str,
                     result: str = "success",
                     severity: AuditSeverity = AuditSeverity.MEDIUM,
                     user_id: Optional[str] = None,
                     user_ip: Optional[str] = None,
                     resource: Optional[str] = None,
                     details: Optional[Dict[str, Any]] = None,
                     session_id: Optional[str] = None,
                     user_agent: Optional[str] = None) -> AuditEvent:
        """Create an audit event object"""
        
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.utcnow().isoformat() + 'Z',
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            user_ip=user_ip,
            resource=resource,
            action=action,
            result=result,
            details=details or {},
            session_id=session_id,
            user_agent=user_agent
        )
        
        # Add integrity checksum if enabled
        if self.enable_integrity_check:
            event_data = json.dumps(asdict(event), sort_keys=True, default=str)
            event.checksum = self._generate_checksum(event_data)
        
        return event
    
    def log_event(self, event: AuditEvent):
        """Log an audit event to all configured outputs"""
        
        # Convert enum values to strings for serialization
        event_dict = asdict(event)
        event_dict['event_type'] = event.event_type.value
        event_dict['severity'] = event.severity.value
        
        # Log to text file
        log_message = (f"ID:{event.event_id} | "
                      f"Type:{event.event_type.value} | "
                      f"User:{event.user_id or 'N/A'} | "
                      f"IP:{event.user_ip or 'N/A'} | "
                      f"Action:{event.action} | "
                      f"Result:{event.result} | "
                      f"Resource:{event.resource or 'N/A'}")
        
        if event.severity == AuditSeverity.CRITICAL:
            self.logger.critical(log_message)
        elif event.severity == AuditSeverity.HIGH:
            self.logger.error(log_message)
        elif event.severity == AuditSeverity.MEDIUM:
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
        
        # Log to JSON file
        try:
            with open(self.json_file, 'a') as f:
                json.dump(event_dict, f, separators=(',', ':'))
                f.write('\n')
        except Exception as e:
            self.logger.error(f"Failed to write to JSON log: {str(e)}")
    
    def log_user_login(self, user_id: str, user_ip: str, 
                      session_id: str, user_agent: str = None,
                      result: str = "success"):
        """Log user login event"""
        event = self._create_event(
            event_type=AuditEventType.USER_LOGIN,
            action="user_login",
            result=result,
            severity=AuditSeverity.MEDIUM if result == "success" else AuditSeverity.HIGH,
            user_id=user_id,
            user_ip=user_ip,
            session_id=session_id,
            user_agent=user_agent,
            details={"login_time": datetime.datetime.utcnow().isoformat()}
        )
        self.log_event(event)
    
    def log_data_access(self, user_id: str, resource: str, 
                       user_ip: str = None, details: Dict[str, Any] = None):
        """Log data access event"""
        event = self._create_event(
            event_type=AuditEventType.DATA_ACCESS,
            action="data_read",
            user_id=user_id,
            user_ip=user_ip,
            resource=resource,
            severity=AuditSeverity.LOW,
            details=details or {}
        )
        self.log_event(event)
    
    def log_data_modification(self, user_id: str, resource: str,
                            changes: Dict[str, Any], user_ip: str = None):
        """Log data modification event"""
        event = self._create_event(
            event_type=AuditEventType.DATA_MODIFICATION,
            action="data_update",
            user_id=user_id,
            user_ip=user_ip,
            resource=resource,
            severity=AuditSeverity.MEDIUM,
            details={
                "changes": changes,
                "modification_time": datetime.datetime.utcnow().isoformat()
            }
        )
        self.log_event(event)
    
    def log_failed_authentication(self, attempted_user: str, 
                                user_ip: str, reason: str):
        """Log failed authentication attempt"""
        event = self._create_event(
            event_type=AuditEventType.FAILED_AUTHENTICATION,
            action="authentication_failed",
            result="failure",
            severity=AuditSeverity.HIGH,
            user_id=attempted_user,
            user_ip=user_ip,
            details={
                "failure_reason": reason,
                "attempt_time": datetime.datetime.utcnow().isoformat()
            }
        )
        self.log_event(event)
    
    def log_system_config_change(self, user_id: str, config_section: str,
                               old_value: Any, new_value: Any, user_ip: str = None):
        """Log system configuration changes"""
        event = self._create_event(
            event_type=AuditEventType.SYSTEM_CONFIG_CHANGE,
            action="config_update",
            user_id=user_id,
            user_ip=user_ip,
            resource=config_section,
            severity=AuditSeverity.HIGH,
            details={
                "old_value": str(old_value),
                "new_value": str(new_value),
                "config_section": config_section
            }
        )
        self.log_event(event)
    
    def log_api_access(self, user_id: str, endpoint: str, method: str,
                      status_code: int, user_ip: str = None, 
                      user_agent: str = None, response_time: float = None):
        """Log API access"""
        result = "success" if 200 <= status_code < 400 else "failure"
        severity = AuditSeverity.LOW if result == "success" else AuditSeverity.MEDIUM
        
        event = self._create_event(
            event_type=AuditEventType.API_ACCESS,
            action=f"{method} {endpoint}",
            result=result,
            severity=severity,
            user_id=user_id,
            user_ip=user_ip,
            resource=endpoint,
            user_agent=user_agent,
            details={
                "http_method": method,
                "status_code": status_code,
                "response_time_ms": response_time
            }
        )
        self.log_event(event)
    
    def verify_integrity(self, event_dict: Dict[str, Any]) -> bool:
        """Verify the integrity of an audit event using its checksum"""
        if not self.enable_integrity_check or 'checksum' not in event_dict:
            return True
        
        stored_checksum = event_dict.pop('checksum')
        event_data = json.dumps(event_dict, sort_keys=True, default=str)
        calculated_checksum = self._generate_checksum(event_data)
        
        return stored_checksum == calculated_checksum


# Example usage and testing
if __name__ == "__main__":
    # Initialize audit logger
    audit = AuditLogger(
        log_file="logs/audit.log",
        json_file="logs/audit.json",
        enable_console=True
    )
    
    # Example audit events
    print("Logging sample audit events...")
    
    # Successful login
    audit.log_user_login(
        user_id="john.doe@company.com",
        user_ip="192.168.1.100",
        session_id="sess_123456789",
        user_agent="Mozilla/5.0..."
    )
    
    # Data access
    audit.log_data_access(
        user_id="john.doe@company.com",
        resource="/api/users/profile",
        user_ip="192.168.1.100",
        details={"query_params": {"include": "personal_info"}}
    )
    
    # Data modification
    audit.log_data_modification(
        user_id="admin@company.com",
        resource="/api/users/123",
        user_ip="192.168.1.50",
        changes={
            "email": {"old": "old@email.com", "new": "new@email.com"},
            "role": {"old": "user", "new": "admin"}
        }
    )
    
    # Failed authentication
    audit.log_failed_authentication(
        attempted_user="hacker@malicious.com",
        user_ip="203.0.113.1",
        reason="Invalid password"
    )
    
    # System configuration change
    audit.log_system_config_change(
        user_id="sysadmin@company.com",
        config_section="security.password_policy",
        old_value="min_length=8",
        new_value="min_length=12",
        user_ip="192.168.1.10"
    )
    
    # API access
    audit.log_api_access(
        user_id="api_user@company.com",
        endpoint="/api/reports/financial",
        method="GET",
        status_code=200,
        user_ip="192.168.1.200",
        response_time=150.5
    )
    
    print("Audit logging complete. Check logs/ directory for output files.")
