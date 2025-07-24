import os

class User:
    def __init__(self, user_id, name, location):
        self.user_id = user_id
        self.name = name
        self.location = location  # e.g., (latitude, longitude) or a predefined location string

class Resource:
    def __init__(self, resource_id, name, allowed_locations):
        self.resource_id = resource_id
        self.name = name
        self.allowed_locations = allowed_locations  # List of allowed locations

class AccessController:
    def __init__(self):
        self.users = {}
        self.resources = {}

    def add_user(self, user):
        self.users[user.user_id] = user

    def add_resource(self, resource):
        self.resources[resource.resource_id] = resource

    def check_access(self, user_id, resource_id):
        if user_id not in self.users:
            return False, "User not found"
        if resource_id not in self.resources:
            return False, "Resource not found"

        user = self.users[user_id]
        resource = self.resources[resource_id]

        if user.location in resource.allowed_locations:
            return True, "Access Granted"
        else:
            return False, f"Access Denied: User location '{user.location}' is not allowed for this resource."

# Example Usage:
if __name__ == "__main__":
    controller = AccessController()

    # Add users
    user1 = User("user1", "Alice", "OfficeA")
    user2 = User("user2", "Bob", "Remote")
    user3 = User("user3", "Charlie", "OfficeB")

    controller.add_user(user1)
    controller.add_user(user2)
    controller.add_user(user3)

    # Add resources
    resource1 = Resource("resource1", "Confidential Document", ["OfficeA", "OfficeB"])
    resource2 = Resource("resource2", "Public Website", ["OfficeA", "OfficeB", "Remote"])

    controller.add_resource(resource1)
    controller.add_resource(resource2)

    # Check access
    access_status1, message1 = controller.check_access("user1", "resource1")
    print(f"User1 access to Resource1: {message1}")

    access_status2, message2 = controller.check_access("user2", "resource1")
    print(f"User2 access to Resource1: {message2}")

    access_status3, message3 = controller.check_access("user3", "resource1")
    print(f"User3 access to Resource1: {message3}")

    access_status4, message4 = controller.check_access("user1", "resource2")
    print(f"User1 access to Resource2: {message4}")

    access_status5, message5 = controller.check_access("user2", "resource2")
    print(f"User2 access to Resource2: {message5}")

    # Example with a user or resource not found
    access_status6, message6 = controller.check_access("user4", "resource1")
    print(f"User4 access to Resource1: {message6}")

    access_status7, message7 = controller.check_access("user1", "resource3")
    print(f"User1 access to Resource3: {message7}")