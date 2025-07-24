#Generate Python code for Event Logging.


import logging
import os

# --- Configuration ---

# Define the log file name
log_filename = 'app_events.log'

# Define the log message format
# %(asctime)s: Time when the LogRecord was created.
# %(levelname)s: Text logging level for the message ('DEBUG', 'INFO', etc.)
# %(name)s: Name of the logger used to log the call.
# %(message)s: The logged message itself.
log_format = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'

# Set the basic configuration for the logging system
# - level: The root logger will be set to the specified severity level.
#          Messages below this severity will be ignored. Common levels:
#          DEBUG, INFO, WARNING, ERROR, CRITICAL
# - filename: Specifies the file to log to. If not specified, logs to console.
# - filemode: If 'filename' is specified, this sets the file open mode.
#             'a' for append (default), 'w' for write (overwrites).
# - format: The format string for the log messages.
logging.basicConfig(
    level=logging.INFO,  # Log INFO level messages and above
    filename=log_filename,
    filemode='a',        # Append to the log file if it exists
    format=log_format,
    datefmt='%Y-%m-%d %H:%M:%S' # Format for the asctime
)

# --- Getting a Logger Instance ---
# It's good practice to use module-specific loggers
# __name__ automatically gets the current module's name
logger = logging.getLogger(__name__)

# You can also create custom named loggers
# data_logger = logging.getLogger('data_processing')

# --- Logging Events ---

logger.debug("This is a debug message. Often used for detailed diagnostics.")
logger.info("Informational message. Confirming things are working as expected.")
logger.warning("Warning message. Indicates something unexpected happened, or a potential problem.")
logger.error("Error message. A more serious problem occurred, the software wasn't able to perform some function.")
logger.critical("Critical error message. A very serious error, indicating the program may be unable to continue running.")

# Example of logging with variable data
user_id = 12345
action = "login"
logger.info(f"User '{user_id}' performed action: '{action}'")

# Example of logging an exception
try:
    result = 10 / 0
except ZeroDivisionError:
    # log.error logs a message with level ERROR on this logger.
    # log.exception logs a message with level ERROR and adds exception information.
    logger.exception("Caught an exception during division.")

print(f"Logging complete. Check the file '{os.path.abspath(log_filename)}'")