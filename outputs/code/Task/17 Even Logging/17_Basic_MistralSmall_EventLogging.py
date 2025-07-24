#Generate Python code for Event Logging.

import logging
from logging.handlers import RotatingFileHandler
import os

# Create a logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Set up the logger
logger = logging.getLogger('eventLogger')
logger.setLevel(logging.DEBUG)  # Set the logging level

# Create a file handler for logging to a file
file_handler = RotatingFileHandler('logs/events.log', maxBytes=1048576, backupCount=5)
file_handler.setLevel(logging.DEBUG)

# Create a console handler for logging to the console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Create a formatter and set it for both handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Function to log events
def log_event(event_type, event_message):
    if event_type.lower() == 'info':
        logger.info(event_message)
    elif event_type.lower() == 'warning':
        logger.warning(event_message)
    elif event_type.lower() == 'error':
        logger.error(event_message)
    elif event_type.lower() == 'debug':
        logger.debug(event_message)
    elif event_type.lower() == 'critical':
        logger.critical(event_message)
    else:
        logger.info(f"Unknown event type: {event_type} - {event_message}")

# Example usage
if __name__ == "__main__":
    log_event('info', 'This is an informational message.')
    log_event('warning', 'This is a warning message.')
    log_event('error', 'This is an error message.')
    log_event('debug', 'This is a debug message.')
    log_event('critical', 'This is a critical message.')
