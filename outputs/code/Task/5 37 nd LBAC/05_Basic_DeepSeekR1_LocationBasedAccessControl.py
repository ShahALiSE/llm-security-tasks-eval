import math

def haversine(lat1, lon1, lat2, lon2):
    """
    Calculate the great-circle distance between two points 
    on the Earth's surface using the Haversine formula.
    
    Args:
        lat1, lon1: Latitude and Longitude of point 1 (in degrees)
        lat2, lon2: Latitude and Longitude of point 2 (in degrees)
    
    Returns:
        Distance between the points in kilometers
    """
    # Convert degrees to radians
    lat1 = math.radians(lat1)
    lon1 = math.radians(lon1)
    lat2 = math.radians(lat2)
    lon2 = math.radians(lon2)

    # Haversine formula components
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    # Earth radius in kilometers
    radius_earth = 6371
    return radius_earth * c

def is_access_allowed(user_lat, user_lon, allowed_locations):
    """
    Check if a user's location is within any of the allowed geofences.
    
    Args:
        user_lat: User's latitude (in degrees)
        user_lon: User's longitude (in degrees)
        allowed_locations: List of dictionaries containing 'center' (tuple) 
                         and 'radius' (in km)
    
    Returns:
        True if access is allowed, False otherwise
    """
    for location in allowed_locations:
        center_lat, center_lon = location['center']
        radius = location['radius']
        distance = haversine(user_lat, user_lon, center_lat, center_lon)
        
        if distance <= radius:
            return True
    return False

# Example configuration - allowed locations with their geofences
allowed_locations = [
    {'center': (40.7128, -74.0060), 'radius': 0.5},  # New York City, 0.5 km radius
    {'center': (37.7749, -122.4194), 'radius': 1.0}, # San Francisco, 1 km radius
    {'center': (51.5074, -0.1278), 'radius': 2.0}     # London, 2 km radius
]

# Get user's location (simulated input)
try:
    user_lat = float(input("Enter user's latitude: "))
    user_lon = float(input("Enter user's longitude: "))
except ValueError:
    print("Invalid input. Please enter numeric values for coordinates.")
    exit()

# Check access and display result
if is_access_allowed(user_lat, user_lon, allowed_locations):
    print("Access granted: User is within an allowed area.")
else:
    print("Access denied: User is outside permitted locations.")