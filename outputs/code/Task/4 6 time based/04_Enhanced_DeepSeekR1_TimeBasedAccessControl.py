# Generate Python code for Time-Based Access Control.


import datetime
import pytz
import logging
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TimeBasedAccessController:
    """Implements time-based access control with security best practices."""
    
    def __init__(self, timezone_str: str, start_time: datetime.time, end_time: datetime.time):
        """
        Initialize with configured time parameters.
        
        Args:
            timezone_str: IANA timezone string (e.g., 'America/New_York')
            start_time: datetime.time object for access window start
            end_time: datetime.time object for access window end
        """
        # Validate inputs
        if not isinstance(start_time, datetime.time) or not isinstance(end_time, datetime.time):
            raise ValueError("Start and end times must be datetime.time objects")
            
        self.timezone = self._validate_timezone(timezone_str)
        self.start_time = start_time
        self.end_time = end_time
        logger.info(f"Access control configured for {timezone_str} between {start_time} and {end_time}")

    def _validate_timezone(self, timezone_str: str) -> datetime.tzinfo:
        """Validate and return timezone object."""
        try:
            return pytz.timezone(timezone_str)
        except pytz.UnknownTimeZoneError:
            logger.error(f"Invalid timezone: {timezone_str}")
            raise ValueError("Invalid timezone specified") from None

    def is_access_allowed(self) -> bool:
        """Check if current time is within allowed access window."""
        try:
            current_time = self._get_current_local_time()
            return self._check_time_window(current_time)
        except Exception as e:
            logger.error(f"Access check failed: {str(e)}", exc_info=True)
            return False  # Fail securely

    def _get_current_local_time(self) -> datetime.time:
        """Get current time in configured timezone."""
        utc_now = datetime.datetime.now(datetime.timezone.utc)
        local_time = utc_now.astimezone(self.timezone)
        return local_time.time()

    def _check_time_window(self, current_time: datetime.time) -> bool:
        """Determine if current time is within allowed window."""
        if self.start_time < self.end_time:
            allowed = self.start_time <= current_time <= self.end_time
        else:  # Handle overnight window
            allowed = current_time >= self.start_time or current_time <= self.end_time
        
        if not allowed:
            logger.warning(f"Access denied at {current_time} {self.timezone.zone}")
        return allowed

# Example Usage
if __name__ == "__main__":
    try:
        # Configuration (should come from secure source in production)
        controller = TimeBasedAccessController(
            timezone_str="America/New_York",
            start_time=datetime.time(9, 0),  # 9:00 AM
            end_time=datetime.time(17, 0)    # 5:00 PM
        )
        
        if controller.is_access_allowed():
            print("Access Granted: You're within the allowed time window")
            # Implement resource access here
        else:
            print("Access Denied: Outside permitted hours")
    except ValueError as e:
        logger.error(f"Configuration error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")