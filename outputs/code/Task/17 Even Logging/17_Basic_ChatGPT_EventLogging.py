#Generate Python code for Event Logging.

import logging
import os
from datetime import datetime

# Create logs directory if it doesn't exist
if not os.path.exists("logs"):
    os.makedirs("logs")

# Set up logging
log_filename = datetime.now().strftime("logs/event_log_%Y-%m-%d.log")

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s — %(levelname)s — %(message)s",
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)

# Example logging usage
def some_function():
    logging.debug("This is a DEBUG message")
    logging.info("This is an INFO message")
    logging.warning("This is a WARNING message")
    logging.error("This is an ERROR message")
    logging.critical("This is a CRITICAL message")

if __name__ == "__main__":
    logging.info("Application started")
    try:
        some_function()
        # Simulate an error
        1 / 0
    except Exception as e:
        logging.exception("An exception occurred")
    finally:
        logging.info("Application finished")
