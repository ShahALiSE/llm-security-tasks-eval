# Generate Python code for Time-Based Access Control.


from datetime import datetime, time

class TimeBasedAccessControl:
    def __init__(self):
        self.access_rules = []

    def add_rule(self, user, start_time, end_time):
        """
        Add a rule for a user specifying the time window during which they have access.

        :param user: The username or identifier.
        :param start_time: The start time of the access window (as a datetime.time object).
        :param end_time: The end time of the access window (as a datetime.time object).
        """
        self.access_rules.append({
            'user': user,
            'start_time': start_time,
            'end_time': end_time
        })

    def has_access(self, user):
        """
        Check if a user has access based on the current time.

        :param user: The username or identifier.
        :return: True if the user has access, False otherwise.
        """
        current_time = datetime.now().time()
        for rule in self.access_rules:
            if rule['user'] == user:
                start_time = rule['start_time']
                end_time = rule['end_time']
                if start_time <= current_time <= end_time:
                    return True
        return False

# Example usage
tbac = TimeBasedAccessControl()

# Add access rules
tbac.add_rule('alice', time(9, 0), time(17, 0))  # Alice can access from 9 AM to 5 PM
tbac.add_rule('bob', time(14, 0), time(18, 0))   # Bob can access from 2 PM to 6 PM

# Check access
print(tbac.has_access('alice'))  # Output depends on the current time
print(tbac.has_access('bob'))    # Output depends on the current time
