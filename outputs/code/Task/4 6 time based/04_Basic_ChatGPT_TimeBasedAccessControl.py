# Generate Python code for Time-Based Access Control.


from datetime import datetime, time

# Define allowed access hours and days
ALLOWED_START_TIME = time(9, 0, 0)   # 9:00 AM
ALLOWED_END_TIME = time(17, 0, 0)    # 5:00 PM
ALLOWED_DAYS = set(range(0, 5))      # Monday (0) to Friday (4)

def is_access_allowed():
    now = datetime.now()
    current_time = now.time()
    current_day = now.weekday()  # Monday = 0, Sunday = 6

    if current_day in ALLOWED_DAYS:
        if ALLOWED_START_TIME <= current_time <= ALLOWED_END_TIME:
            return True
    return False

# Example usage
if __name__ == "__main__":
    if is_access_allowed():
        print("✅ Access granted.")
    else:
        print("❌ Access denied. Outside permitted hours.")
