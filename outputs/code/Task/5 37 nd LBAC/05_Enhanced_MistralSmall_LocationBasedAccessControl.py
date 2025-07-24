from geopy.distance import geodesic

class LocationBasedAccessControl:
    def __init__(self, access_rules):
        """
        Initialize the access control system with a set of access rules.

        :param access_rules: A dictionary where keys are location names and values are tuples of (latitude, longitude, radius).
        """
        self.access_rules = access_rules

    def get_user_location(self):
        """
        Simulate getting the user's current location.
        In a real application, this would interface with a GPS or geolocation service.

        :return: A tuple of (latitude, longitude).
        """
        # Example: Replace with actual geolocation code
        return (52.5200, 13.4050)  # Example coordinates for Berlin, Germany

    def check_access(self, user_location):
        """
        Check if the user has access based on their current location.

        :param user_location: A tuple of (latitude, longitude).
        :return: Boolean indicating whether access is granted.
        """
        for location_name, (lat, lon, radius) in self.access_rules.items():
            distance = geodesic(user_location, (lat, lon)).meters
            if distance <= radius:
                print(f"Access granted: Within {radius} meters of {location_name}.")
                return True
        print("Access denied: Not within any allowed location.")
        return False

    def run(self):
        """
        Run the access control check.
        """
        user_location = self.get_user_location()
        print(f"User location: {user_location}")
        access_granted = self.check_access(user_location)
        return access_granted

# Example access rules: (location_name, (latitude, longitude, radius in meters))
access_rules = {
    "Office": (52.5200, 13.4050, 100),  # Example: Office in Berlin
    "Home": (52.5100, 13.4100, 50),    # Example: Home in Berlin
}

# Initialize the access control system
lbac = LocationBasedAccessControl(access_rules)

# Run the access control check
lbac.run()
