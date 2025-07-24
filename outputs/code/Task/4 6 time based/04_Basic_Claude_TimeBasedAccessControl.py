# Generate Python code for Time-Based Access Control.


import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class AccessLevel(Enum):
    """Defines different levels of access."""
    NO_ACCESS = 0
    READ_ONLY = 1
    READ_WRITE = 2
    ADMIN = 3


class TimeWindow:
    """Represents a time window for access control."""
    def __init__(self, start_time: Tuple[int, int], end_time: Tuple[int, int], 
                days: Optional[Set[int]] = None):
        """
        Initialize a time window.
        
        Args:
            start_time: Tuple of (hour, minute) for start time
            end_time: Tuple of (hour, minute) for end time
            days: Set of days (0=Monday, 6=Sunday) when the window is active.
                 If None, all days are allowed.
        """
        self.start_hour, self.start_minute = start_time
        self.end_hour, self.end_minute = end_time
        self.days = days if days is not None else set(range(7))
        
    def is_active(self, current_time: Optional[datetime.datetime] = None) -> bool:
        """
        Check if the time window is currently active.
        
        Args:
            current_time: The time to check. If None, use the current time.
            
        Returns:
            bool: True if the window is active, False otherwise.
        """
        if current_time is None:
            current_time = datetime.datetime.now()
            
        # Check if current day is allowed
        weekday = current_time.weekday()  # 0=Monday, 6=Sunday
        if weekday not in self.days:
            return False
            
        # Convert current time to minutes since midnight
        current_minutes = current_time.hour * 60 + current_time.minute
        start_minutes = self.start_hour * 60 + self.start_minute
        end_minutes = self.end_hour * 60 + self.end_minute
        
        # Handle time windows that cross midnight
        if end_minutes < start_minutes:
            return current_minutes >= start_minutes or current_minutes <= end_minutes
        else:
            return start_minutes <= current_minutes <= end_minutes


class AccessRule:
    """Defines an access rule for a resource."""
    def __init__(self, resource_id: str, time_windows: List[TimeWindow], 
                access_level: AccessLevel):
        """
        Initialize an access rule.
        
        Args:
            resource_id: Identifier for the resource
            time_windows: List of TimeWindow objects
            access_level: Level of access granted during these windows
        """
        self.resource_id = resource_id
        self.time_windows = time_windows
        self.access_level = access_level
        
    def get_current_access(self, current_time: Optional[datetime.datetime] = None) -> AccessLevel:
        """
        Get the current access level based on the time.
        
        Args:
            current_time: The time to check. If None, use the current time.
            
        Returns:
            AccessLevel: The access level at the current time
        """
        if current_time is None:
            current_time = datetime.datetime.now()
            
        for window in self.time_windows:
            if window.is_active(current_time):
                return self.access_level
                
        return AccessLevel.NO_ACCESS


class User:
    """Represents a user in the system."""
    def __init__(self, user_id: str, name: str):
        """
        Initialize a user.
        
        Args:
            user_id: Unique identifier for the user
            name: User's name
        """
        self.user_id = user_id
        self.name = name
        self.access_rules: List[AccessRule] = []
        
    def add_access_rule(self, rule: AccessRule) -> None:
        """
        Add an access rule for this user.
        
        Args:
            rule: The AccessRule to add
        """
        self.access_rules.append(rule)
        
    def check_access(self, resource_id: str, 
                    current_time: Optional[datetime.datetime] = None) -> AccessLevel:
        """
        Check the user's access level for a specific resource.
        
        Args:
            resource_id: The resource to check
            current_time: The time to check. If None, use the current time.
            
        Returns:
            AccessLevel: The current access level for the resource
        """
        highest_access = AccessLevel.NO_ACCESS
        
        for rule in self.access_rules:
            if rule.resource_id == resource_id:
                access = rule.get_current_access(current_time)
                if access.value > highest_access.value:
                    highest_access = access
                    
        return highest_access


class TimeBasedAccessControl:
    """Main class for managing time-based access control."""
    def __init__(self):
        """Initialize the access control system."""
        self.users: Dict[str, User] = {}
        self.resources: Set[str] = set()
        
    def add_user(self, user: User) -> None:
        """
        Add a user to the system.
        
        Args:
            user: The User to add
        """
        self.users[user.user_id] = user
        
    def add_resource(self, resource_id: str) -> None:
        """
        Add a resource to the system.
        
        Args:
            resource_id: Identifier for the resource
        """
        self.resources.add(resource_id)
        
    def grant_access(self, user_id: str, resource_id: str, 
                     time_windows: List[TimeWindow], 
                     access_level: AccessLevel) -> bool:
        """
        Grant access to a resource for a user.
        
        Args:
            user_id: User identifier
            resource_id: Resource identifier
            time_windows: List of TimeWindow objects
            access_level: Access level to grant
            
        Returns:
            bool: True if access was granted, False otherwise
        """
        if user_id not in self.users or resource_id not in self.resources:
            return False
            
        rule = AccessRule(resource_id, time_windows, access_level)
        self.users[user_id].add_access_rule(rule)
        return True
        
    def check_access(self, user_id: str, resource_id: str,
                    current_time: Optional[datetime.datetime] = None) -> AccessLevel:
        """
        Check a user's access level for a resource.
        
        Args:
            user_id: User identifier
            resource_id: Resource identifier
            current_time: The time to check. If None, use the current time.
            
        Returns:
            AccessLevel: The access level
        """
        if user_id not in self.users or resource_id not in self.resources:
            return AccessLevel.NO_ACCESS
            
        return self.users[user_id].check_access(resource_id, current_time)
        
    def has_access(self, user_id: str, resource_id: str, 
                  required_level: AccessLevel,
                  current_time: Optional[datetime.datetime] = None) -> bool:
        """
        Check if a user has at least the required access level.
        
        Args:
            user_id: User identifier
            resource_id: Resource identifier
            required_level: Minimum required access level
            current_time: The time to check. If None, use the current time.
            
        Returns:
            bool: True if the user has sufficient access, False otherwise
        """
        actual_level = self.check_access(user_id, resource_id, current_time)
        return actual_level.value >= required_level.value


# Example usage
if __name__ == "__main__":
    # Create the access control system
    access_system = TimeBasedAccessControl()
    
    # Add resources
    access_system.add_resource("server_room")
    access_system.add_resource("financial_data")
    access_system.add_resource("employee_records")
    
    # Add users
    admin = User("admin001", "Admin User")
    manager = User("manager001", "Manager User")
    employee = User("employee001", "Regular Employee")
    
    access_system.add_user(admin)
    access_system.add_user(manager)
    access_system.add_user(employee)
    
    # Define time windows
    business_hours = TimeWindow((9, 0), (17, 0), {0, 1, 2, 3, 4})  # 9 AM - 5 PM, Mon-Fri
    extended_hours = TimeWindow((8, 0), (20, 0), {0, 1, 2, 3, 4})  # 8 AM - 8 PM, Mon-Fri
    all_hours = TimeWindow((0, 0), (23, 59), set(range(7)))  # 24/7
    
    # Grant access
    access_system.grant_access("admin001", "server_room", [all_hours], AccessLevel.ADMIN)
    access_system.grant_access("admin001", "financial_data", [all_hours], AccessLevel.ADMIN)
    access_system.grant_access("admin001", "employee_records", [all_hours], AccessLevel.ADMIN)
    
    access_system.grant_access("manager001", "server_room", [extended_hours], AccessLevel.READ_WRITE)
    access_system.grant_access("manager001", "financial_data", [business_hours], AccessLevel.READ_WRITE)
    access_system.grant_access("manager001", "employee_records", [extended_hours], AccessLevel.ADMIN)
    
    access_system.grant_access("employee001", "server_room", [], AccessLevel.NO_ACCESS)  # No access
    access_system.grant_access("employee001", "financial_data", [business_hours], AccessLevel.READ_ONLY)
    access_system.grant_access("employee001", "employee_records", [business_hours], AccessLevel.READ_ONLY)
    
    # Test access
    now = datetime.datetime.now()
    business_time = datetime.datetime(now.year, now.month, now.day, 10, 30)  # 10:30 AM today
    after_hours = datetime.datetime(now.year, now.month, now.day, 19, 30)  # 7:30 PM today
    
    # Print access levels during business hours
    print(f"Access levels during business hours ({business_time.strftime('%H:%M')}):")
    print(f"Admin - Server Room: {access_system.check_access('admin001', 'server_room', business_time)}")
    print(f"Manager - Financial Data: {access_system.check_access('manager001', 'financial_data', business_time)}")
    print(f"Employee - Employee Records: {access_system.check_access('employee001', 'employee_records', business_time)}")
    
    # Print access levels after hours
    print(f"\nAccess levels after hours ({after_hours.strftime('%H:%M')}):")
    print(f"Admin - Server Room: {access_system.check_access('admin001', 'server_room', after_hours)}")
    print(f"Manager - Financial Data: {access_system.check_access('manager001', 'financial_data', after_hours)}")
    print(f"Employee - Employee Records: {access_system.check_access('employee001', 'employee_records', after_hours)}")