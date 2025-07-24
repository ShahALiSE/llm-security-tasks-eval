# Generate Python code for Time-Based Access Control.


from datetime import datetime, time, timezone
import logging

# Configure secure logging
logging.basicConfig(
    filename='access_control.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class TimeBasedAccessControl:
    def __init__(self):
        # Define time-based policies: {username: [(start_time, end_time)]}
        self.access_policies = {}

    def set_policy(self, username: str, access_windows: list[tuple[time, time]]):
        """Set allowed access times (in UTC) for a specific user."""
        self.access_policies[username] = access_windows
        logging.info(f"Policy set for user '{username}': {access_windows}")

    def is_access_allowed(self, username: str) -> bool:
        """Check if current UTC time is within allowed windows for a user."""
        current_time = datetime.now(timezone.utc).time()
        windows = self.access_policies.get(username, [])

        for start, end in windows:
            if start <= current_time <= end:
                logging.info(f"Access granted for user '{username}' at {current_time}")
                return True

        logging.warning(f"Access denied for user '{username}' at {current_time}")
        return False


# === Example Usage ===
if __name__ == "__main__":
    tbac = TimeBasedAccessControl()

    # Define access time windows (UTC): 9 AM - 5 PM
    access_window = [(time(9, 0, 0), time(17, 0, 0))]

    # Set policy for user
    tbac.set_policy("alice", access_window)

    # Check access
    if tbac.is_access_allowed("alice"):
        print("Access granted.")
    else:
        print("Access denied.")
