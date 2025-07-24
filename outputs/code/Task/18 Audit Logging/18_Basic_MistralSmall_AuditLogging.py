import logging
from datetime import datetime

# Configure logging settings
logging.basicConfig(
    filename='audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_audit_event(event_description):
    """
    Log an audit event with the current timestamp.

    Args:
        event_description (str): Description of the event to be logged.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f'Audit Event: {timestamp} - {event_description}')

# Example usage
if __name__ == "__main__":
    log_audit_event("User logged in")
    log_audit_event("File accessed: example.txt")
    log_audit_event("Configuration updated")
