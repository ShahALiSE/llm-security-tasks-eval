# Generate Python code for Time-Based Access Control.


 import datetime
import functools
import logging
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # Use zoneinfo (Python 3.9+)
# For Python < 3.9, you would use pytz:
# import pytz

# --- Configuration ---
# Set up basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a custom exception for clarity
class AccessDeniedError(PermissionError):
    """Custom exception raised when access is denied due to time policy."""
    pass

# --- Helper Function for Time Check ---
def is_access_allowed(
    allowed_weekdays: set[int], # Monday=0, Sunday=6
    start_time_str: str,        # HH:MM:SS format
    end_time_str: str,          # HH:MM:SS format
    timezone_str: str = "UTC"   # IANA timezone database name (e.g., 'UTC', 'Europe/Berlin')
) -> bool:
    """
    Checks if the current time falls within the allowed window and weekday.

    Args:
        allowed_weekdays: A set of integers representing allowed weekdays (0-6).
        start_time_str: The start time in 'HH:MM:SS' format.
        end_time_str: The end time in 'HH:MM:SS' format.
        timezone_str: The IANA timezone name. Defaults to UTC.

    Returns:
        True if access is allowed, False otherwise.

    Raises:
        ValueError: If time strings are invalid or timezone is not found.
    """
    try:
        # 1. Get the current time in the specified timezone
        # It's crucial to use a specific timezone to avoid ambiguity. UTC is often preferred
        # for backend logic unless rules are inherently local.
        target_tz = ZoneInfo(timezone_str)
        # For pytz: target_tz = pytz.timezone(timezone_str)

        now = datetime.datetime.now(target_tz)
        current_time = now.time()
        current_weekday = now.weekday()

        # 2. Parse start and end times
        start_time = datetime.time.fromisoformat(start_time_str)
        end_time = datetime.time.fromisoformat(end_time_str)

    except ZoneInfoNotFoundError:
        logging.error(f"Timezone '{timezone_str}' not found. Using system default might be unreliable.")
        # Or raise a specific configuration error
        raise ValueError(f"Invalid timezone specified: {timezone_str}")
    except ValueError as e:
        logging.error(f"Invalid time format provided: {e}")
        raise ValueError(f"Invalid time format for start/end time: {e}") from e

    # 3. Check weekday
    if current_weekday not in allowed_weekdays:
        logging.debug(f"Access denied: Current weekday {current_weekday} not in allowed {allowed_weekdays}")
        return False

    # 4. Check time window (handles overnight periods, e.g., 22:00 to 06:00)
    if start_time <= end_time:
        # Normal case: Start time is before or equal to end time (e.g., 09:00 to 17:00)
        if not (start_time <= current_time < end_time):
            logging.debug(f"Access denied: Current time {current_time} outside window {start_time}-{end_time}")
            return False
    else:
        # Overnight case: Start time is after end time (e.g., 22:00 to 06:00)
        if not (current_time >= start_time or current_time < end_time):
             logging.debug(f"Access denied: Current time {current_time} outside overnight window {start_time}-{end_time}")
             return False

    # 5. If all checks pass, access is allowed
    logging.debug(f"Access allowed: Current time {current_time} within window {start_time}-{end_time} on weekday {current_weekday}")
    return True

# --- The Decorator ---
def time_based_access(
    allowed_weekdays: set[int],
    start_time_str: str,
    end_time_str: str,
    timezone_str: str = "UTC",
    log_denial: bool = True # Option to log denied attempts
):
    """
    Decorator to enforce time-based access control on a function.

    Args:
        allowed_weekdays: Set of integers for allowed weekdays (0=Monday, 6=Sunday).
        start_time_str: Start time string ('HH:MM:SS').
        end_time_str: End time string ('HH:MM:SS').
        timezone_str: IANA timezone name (default: 'UTC').
        log_denial: Whether to log denied access attempts (default: True).
    """
    def decorator(func):
        @functools.wraps(func) # Preserves function metadata (name, docstring)
        def wrapper(*args, **kwargs):
            try:
                allowed = is_access_allowed(
                    allowed_weekdays=allowed_weekdays,
                    start_time_str=start_time_str,
                    end_time_str=end_time_str,
                    timezone_str=timezone_str
                )
            except ValueError as e:
                # Handle invalid configuration gracefully (e.g., log and deny access)
                logging.error(f"TBAC configuration error for {func.__name__}: {e}. Denying access.")
                raise AccessDeniedError(f"Access to '{func.__name__}' denied due to configuration error.") from e

            if allowed:
                logging.info(f"Access granted to function '{func.__name__}'.")
                return func(*args, **kwargs)
            else:
                if log_denial:
                    logging.warning(f"Access denied to function '{func.__name__}' due to time restrictions.")
                # Raise a specific, catchable exception
                raise AccessDeniedError(f"Access to '{func.__name__}' is restricted at this time.")
        return wrapper
    return decorator

# --- Example Usage ---

# Define access policies (could be loaded from config file/DB)
BUSINESS_HOURS_BERLIN = {
    "allowed_weekdays": {0, 1, 2, 3, 4},  # Monday to Friday
    "start_time_str": "09:00:00",
    "end_time_str": "17:00:00",
    "timezone_str": "Europe/Berlin"
}

NIGHTLY_BATCH_JOB_UTC = {
    "allowed_weekdays": {0, 1, 2, 3, 4, 5, 6}, # Everyday
    "start_time_str": "23:00:00",             # 11 PM
    "end_time_str": "04:00:00",               # 4 AM (overnight)
    "timezone_str": "UTC"
}

# Apply the decorator to functions
@time_based_access(**BUSINESS_HOURS_BERLIN)
def generate_report(customer_id: int):
    """Generates a customer report. Only accessible during Berlin business hours."""
    print(f"Generating report for customer {customer_id}...")
    # Simulate work
    return {"report_id": f"REP-{customer_id}-{datetime.datetime.now().timestamp()}"}

@time_based_access(**NIGHTLY_BATCH_JOB_UTC)
def run_batch_process():
    """Runs a batch process. Only accessible during the UTC night window."""
    print("Starting nightly batch process...")
    # Simulate work
    print("Batch process finished.")
    return True

@time_based_access(allowed_weekdays={6}, start_time_str="12:00:00", end_time_str="14:00:00", timezone_str="America/New_York")
def sunday_special_task():
    """A task only allowed on Sunday afternoons in New York time."""
    print("Performing the special Sunday task.")
    return "Sunday task complete"

# --- Testing the Access Control ---
if __name__ == "__main__":
    print(f"Current UTC time: {datetime.datetime.now(ZoneInfo('UTC'))}")
    print(f"Current Berlin time: {datetime.datetime.now(ZoneInfo('Europe/Berlin'))}")
    print(f"Current New York time: {datetime.datetime.now(ZoneInfo('America/New_York'))}")
    print("-" * 20)

    print("Attempting to generate report...")
    try:
        report = generate_report(customer_id=123)
        print(f"Report generated successfully: {report}")
    except AccessDeniedError as e:
        print(f"Report generation failed: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    print("-" * 20)
    print("Attempting to run batch process...")
    try:
        result = run_batch_process()
        print(f"Batch process ran successfully: {result}")
    except AccessDeniedError as e:
        print(f"Batch process failed: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    print("-" * 20)
    print("Attempting to run Sunday special task...")
    try:
        result = sunday_special_task()
        print(f"Sunday task ran successfully: {result}")
    except AccessDeniedError as e:
        print(f"Sunday task failed: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")