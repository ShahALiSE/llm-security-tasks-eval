import json
import datetime
import math
from typing import Dict, List, Tuple, Optional


class LocationBasedAccessControl:
    """
    A system that manages access control based on user location.
    """
    
    def __init__(self, config_file: str = None):
        """
        Initialize the Location-Based Access Control system.
        
        Args:
            config_file: Path to configuration file (optional)
        """
        # Default configuration
        self.secure_zones = {
            "server_room": {
                "center": (34.0522, -118.2437),  # Lat, Long
                "radius": 50,  # meters
                "allowed_roles": ["admin", "it_staff"],
                "time_restrictions": {
                    "start_time": "08:00",
                    "end_time": "20:00"
                }
            },
            "executive_office": {
                "center": (34.0525, -118.2430),
                "radius": 30,
                "allowed_roles": ["executive", "admin"],
                "time_restrictions": {
                    "start_time": "07:00",
                    "end_time": "19:00"
                }
            }
        }
        
        self.user_database = {
            "user123": {
                "name": "John Doe",
                "roles": ["employee", "it_staff"],
                "access_history": []
            },
            "user456": {
                "name": "Jane Smith",
                "roles": ["employee", "executive"],
                "access_history": []
            },
            "user789": {
                "name": "Bob Johnson",
                "roles": ["employee"],
                "access_history": []
            }
        }
        
        # Load configuration if provided
        if config_file:
            self.load_config(config_file)
    
    def load_config(self, config_file: str) -> None:
        """
        Load configuration from a JSON file.
        
        Args:
            config_file: Path to configuration file
        """
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                
            if "secure_zones" in config:
                self.secure_zones = config["secure_zones"]
            if "user_database" in config:
                self.user_database = config["user_database"]
                
            print(f"Configuration loaded from {config_file}")
        except Exception as e:
            print(f"Error loading configuration: {e}")
    
    def save_config(self, config_file: str) -> None:
        """
        Save current configuration to a JSON file.
        
        Args:
            config_file: Path to save configuration file
        """
        config = {
            "secure_zones": self.secure_zones,
            "user_database": self.user_database
        }
        
        try:
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=4)
            print(f"Configuration saved to {config_file}")
        except Exception as e:
            print(f"Error saving configuration: {e}")
    
    def calculate_distance(self, point1: Tuple[float, float], point2: Tuple[float, float]) -> float:
        """
        Calculate the distance between two geographic points (in meters).
        Uses the Haversine formula for great-circle distance.
        
        Args:
            point1: (latitude, longitude) of first point
            point2: (latitude, longitude) of second point
            
        Returns:
            Distance in meters
        """
        # Earth radius in meters
        EARTH_RADIUS = 6371000
        
        lat1, lon1 = point1
        lat2, lon2 = point2
        
        # Convert to radians
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)
        
        # Haversine formula
        dlon = lon2_rad - lon1_rad
        dlat = lat2_rad - lat1_rad
        
        a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        distance = EARTH_RADIUS * c
        
        return distance
    
    def is_within_time_restrictions(self, zone_id: str) -> bool:
        """
        Check if current time is within the allowed time restrictions for a zone.
        
        Args:
            zone_id: ID of the zone
            
        Returns:
            Boolean indicating whether current time is within allowed time
        """
        if zone_id not in self.secure_zones:
            return False
            
        zone = self.secure_zones[zone_id]
        if "time_restrictions" not in zone:
            return True  # No time restrictions means always allowed
            
        time_restrictions = zone["time_restrictions"]
        current_time = datetime.datetime.now().time()
        
        start_time = datetime.datetime.strptime(time_restrictions["start_time"], "%H:%M").time()
        end_time = datetime.datetime.strptime(time_restrictions["end_time"], "%H:%M").time()
        
        return start_time <= current_time <= end_time
    
    def check_access(self, user_id: str, location: Tuple[float, float], zone_id: str) -> bool:
        """
        Check if a user has access to a specific zone based on their location and roles.
        
        Args:
            user_id: User identifier
            location: (latitude, longitude) of the user
            zone_id: ID of the zone to check access for
            
        Returns:
            Boolean indicating whether access is granted
        """
        # Validate inputs
        if user_id not in self.user_database:
            print(f"Unknown user: {user_id}")
            return False
            
        if zone_id not in self.secure_zones:
            print(f"Unknown zone: {zone_id}")
            return False
        
        user = self.user_database[user_id]
        zone = self.secure_zones[zone_id]
        
        # Check if user is within zone radius
        distance = self.calculate_distance(location, zone["center"])
        if distance > zone["radius"]:
            print(f"User {user_id} is outside of zone {zone_id} (distance: {distance:.2f}m)")
            return False
        
        # Check if user has a role that allows access to this zone
        has_permission = any(role in zone["allowed_roles"] for role in user["roles"])
        if not has_permission:
            print(f"User {user_id} does not have permission for zone {zone_id}")
            return False
        
        # Check time restrictions
        if not self.is_within_time_restrictions(zone_id):
            print(f"Access to {zone_id} is restricted at current time")
            return False
        
        # All checks passed, log access and return success
        self._log_access(user_id, zone_id, location, True)
        return True
    
    def _log_access(self, user_id: str, zone_id: str, location: Tuple[float, float], granted: bool) -> None:
        """
        Log access attempt to user history.
        
        Args:
            user_id: User identifier
            zone_id: ID of the zone
            location: (latitude, longitude) of the user
            granted: Whether access was granted
        """
        timestamp = datetime.datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "zone_id": zone_id,
            "location": location,
            "granted": granted
        }
        
        self.user_database[user_id]["access_history"].append(log_entry)
    
    def add_user(self, user_id: str, name: str, roles: List[str]) -> bool:
        """
        Add a new user to the system.
        
        Args:
            user_id: Unique user identifier
            name: User's name
            roles: List of roles assigned to the user
            
        Returns:
            Boolean indicating success
        """
        if user_id in self.user_database:
            print(f"User {user_id} already exists")
            return False
            
        self.user_database[user_id] = {
            "name": name,
            "roles": roles,
            "access_history": []
        }
        print(f"Added user {user_id}: {name}")
        return True
    
    def add_secure_zone(self, zone_id: str, center: Tuple[float, float], radius: float, 
                       allowed_roles: List[str], time_restrictions: Optional[Dict] = None) -> bool:
        """
        Add a new secure zone to the system.
        
        Args:
            zone_id: Unique zone identifier
            center: (latitude, longitude) of zone center
            radius: Radius of zone in meters
            allowed_roles: List of roles allowed to access this zone
            time_restrictions: Optional dict with start_time and end_time (format: "HH:MM")
            
        Returns:
            Boolean indicating success
        """
        if zone_id in self.secure_zones:
            print(f"Zone {zone_id} already exists")
            return False
            
        self.secure_zones[zone_id] = {
            "center": center,
            "radius": radius,
            "allowed_roles": allowed_roles,
        }
        
        if time_restrictions:
            self.secure_zones[zone_id]["time_restrictions"] = time_restrictions
            
        print(f"Added secure zone {zone_id}")
        return True
    
    def get_user_access_history(self, user_id: str) -> List[Dict]:
        """
        Get the access history for a specific user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of access history entries
        """
        if user_id not in self.user_database:
            print(f"Unknown user: {user_id}")
            return []
            
        return self.user_database[user_id]["access_history"]
    
    def get_accessible_zones(self, user_id: str, location: Tuple[float, float]) -> List[str]:
        """
        Get a list of zones a user can access from their current location.
        
        Args:
            user_id: User identifier
            location: (latitude, longitude) of the user
            
        Returns:
            List of zone IDs the user can access
        """
        if user_id not in self.user_database:
            print(f"Unknown user: {user_id}")
            return []
            
        accessible_zones = []
        
        for zone_id in self.secure_zones:
            if self.check_access(user_id, location, zone_id):
                accessible_zones.append(zone_id)
                
        return accessible_zones


# Example usage
if __name__ == "__main__":
    # Create a Location-Based Access Control system
    lbac = LocationBasedAccessControl()
    
    # Add some additional users and zones
    lbac.add_user("user101", "Alice Brown", ["employee", "admin"])
    lbac.add_secure_zone(
        "research_lab", 
        (34.0530, -118.2440), 
        40, 
        ["researcher", "admin"],
        {"start_time": "09:00", "end_time": "17:00"}
    )
    
    # Test access control
    print("\nTesting access control:")
    
    # User with appropriate role within zone radius during allowed hours
    user_location = (34.0523, -118.2436)  # Near server room
    access_granted = lbac.check_access("user123", user_location, "server_room")
    print(f"Access to server room for IT staff: {access_granted}")
    
    # User outside zone radius
    far_location = (34.0600, -118.2500)  # Far from any zone
    access_granted = lbac.check_access("user456", far_location, "executive_office")
    print(f"Access to executive office from distant location: {access_granted}")
    
    # User without appropriate role
    access_granted = lbac.check_access("user789", user_location, "server_room")
    print(f"Access to server room for regular employee: {access_granted}")
    
    # Get accessible zones for a user
    user_location = (34.0524, -118.2435)  # Near server room and executive office
    zones = lbac.get_accessible_zones("user101", user_location)
    print(f"\nAccessible zones for admin user: {zones}")
    
    # Save configuration to file
    lbac.save_config("lbac_config.json")
