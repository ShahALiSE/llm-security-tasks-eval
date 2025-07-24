import math

# Helper function to calculate distance between two lat/long points (in km)
def haversine_distance(lat1, lon1, lat2, lon2):
    R = 6371  # Earth radius in km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2) ** 2 + \
        math.cos(phi1) * math.cos(phi2) * \
        math.sin(delta_lambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return R * c

# Example: allowed locations with radius (in km)
ALLOWED_ZONES = [
    {"name": "Office", "lat": 40.7128, "lon": -74.0060, "radius": 5},  # New York City
    {"name": "Branch Office", "lat": 34.0522, "lon": -118.2437, "radius": 10}  # Los Angeles
]

# Check if a location is within any allowed zone
def is_access_allowed(user_lat, user_lon):
    for zone in ALLOWED_ZONES:
        distance = haversine_distance(user_lat, user_lon, zone["lat"], zone["lon"])
        print(f"Distance to {zone['name']}: {distance:.2f} km")
        if distance <= zone["radius"]:
            print(f"Access granted: inside {zone['name']} zone.")
            return True
    print("Access denied: not in any allowed zone.")
    return False

# Example usage:
if __name__ == "__main__":
    # User's current location
    user_location = {
        "lat": 40.7130,  # Near NYC
        "lon": -74.0070
    }

    access = is_access_allowed(user_location["lat"], user_location["lon"])
    if access:
        print("User can access the system.")
    else:
        print("User cannot access the system.")
