#Generate secure Python code for Event Logging. Ensure security best practices.

import logging
import logging.config
import logging.handlers
import os
import json
import re
from datetime import datetime

# --- Configuration (Best Practice: Load from file/env vars) ---
# Example using dictConfig - more flexible than fileConfig
# In a real app, load this dictionary from a YAML/JSON file or build from env vars.

LOG_DIR = "logs" # Ensure this directory exists and has secure permissions
LOG_FILENAME = "app_events.log"
LOG_FILE_PATH = os.path.join(LOG_DIR, LOG_FILENAME)

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)
# IMPORTANT: Set secure permissions on the log directory and files (OS-level)
# Example (Linux/macOS): os.chmod(LOG_DIR, 0o700) # Owner read/write/execute only
# File permissions are often handled by the RotatingFileHandler's default mode,
# but verify they meet your security requirements.

# Define a custom JSON formatter for structured logging
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(), # Use getMessage() to handle args
            "source": f"{record.pathname}:{record.lineno}",
        }
        if record.exc_info:
            log_record['exception'] = self.formatException(record.exc_info)
        if hasattr(record, 'extra_data') and record.extra_data:
            log_record.update(record.extra_data) # Merge extra context
        return json.dumps(log_record)

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False, # Keep default loggers (e.g., for libraries)
    "formatters": {
        "standard": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "json": {
            # Define the custom class for JSON formatting
            "()": JsonFormatter,
            "datefmt": "%Y-%m-%dT%H:%M:%S%z", # ISO 8601 format
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG", # Log DEBUG and above to console (for development)
            "formatter": "standard",
            "stream": "ext://sys.stderr", # Use stderr for logs
        },
        "rotating_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "INFO", # Log INFO and above to file (for production)
            "formatter": "json", # Use JSON format for file logs
            "filename": LOG_FILE_PATH,
            "maxBytes": 10 * 1024 * 1024,  # 10 MB per file
            "backupCount": 5,  # Keep 5 backup files
            "encoding": "utf-8", # Explicitly set encoding
            # 'mode': 'a' is default (append)
        },
        # Example: Syslog Handler (common on Linux/macOS)
        # 'syslog': {
        #     'class': 'logging.handlers.SysLogHandler',
        #     'level': 'WARNING',
        #     'formatter': 'standard',
        #     'address': '/dev/log', # or ('hostname', 514) for remote
        # },
    },
    "loggers": {
        "": {  # Root logger
            "level": "DEBUG", # Set root logger level (lowest level handled)
            # Apply handlers: console for dev, file for persistent/prod logs
            "handlers": ["console", "rotating_file"],
            # Add 'syslog' here if using it
            "propagate": False, # Prevent root logger messages being handled twice if specific loggers also use these handlers
        },
        "myapp": { # Specific logger for your application
            "level": "INFO", # App-specific level override
            "handlers": ["console", "rotating_file"], # Or specific handlers
            "propagate": False, # Don't pass messages up to the root logger if handled here
        },
        "sensitive_module": { # Example: Logger for a module handling sensitive data
             "level": "WARNING", # Log only warnings or higher to avoid leaking info
             "handlers": ["rotating_file"], # Maybe only to file, not console
             "propagate": False,
        },
         "external_library": { # Example: Control verbose library logging
             "level": "WARNING", # Suppress INFO/DEBUG from a noisy library
             "handlers": ["rotating_file"],
             "propagate": False,
         }
    },
}

# --- Setup Function ---
def setup_logging():
    """Configures logging using the defined dictionary."""
    try:
        logging.config.dictConfig(LOGGING_CONFIG)
        logging.info("Logging setup successfully.")
        # Test permissions (optional, more robust checks needed for prod)
        if not os.access(LOG_FILE_PATH, os.W_OK):
             logging.warning(f"Log file {LOG_FILE_PATH} might not be writable.")
    except Exception as e:
        # Fallback basic logging if setup fails
        logging.basicConfig(level=logging.ERROR)
        logging.exception("Failed to configure logging!")
        # Depending on the application, you might want to exit here
        # raise SystemExit(f"Logging configuration failed: {e}") from e

# --- Secure Logging Practices ---

# Basic sanitization (Optional - Use cautiously, parameter substitution is primary)
# Remove characters that might break simple log viewers or cause issues.
# Avoid complex regex that could lead to ReDoS.
_newline_pattern = re.compile(r'[\r\n]+')
def sanitize_log_input(input_string):
    """Removes newlines and carriage returns from a string."""
    if not isinstance(input_string, str):
        input_string = str(input_string) # Ensure it's a string
    # Replace newlines/CRs with a space or remove them
    sanitized = _newline_pattern.sub(' ', input_string)
    # Add more sanitization if needed (e.g., control characters), but keep it simple.
    return sanitized

# --- Example Usage ---
if __name__ == "__main__":
    setup_logging()

    # Get loggers for different parts of an imaginary application
    app_logger = logging.getLogger("myapp")
    sensitive_logger = logging.getLogger("sensitive_module")
    root_logger = logging.getLogger() # Get the root logger

    app_logger.info("Application started.")
    root_logger.debug("This is a root debug message.") # May go to console based on config

    # --- SECURE LOGGING EXAMPLE ---
    user_input = "User provided this data\npotentially with newlines or <script>alert('bad')</script>"
    user_id = "user123"
    action = "login_attempt"

    # GOOD: Use parameter substitution. The logger handles escaping safely.
    app_logger.info("User %s performed action: %s", user_id, action)
    app_logger.warning("Failed login attempt for user: %s", user_id)

    # BAD: Do NOT format the string *before* passing to the logger
    # This is vulnerable to log injection if user_input contains format specifiers
    # or characters that break log parsing or log viewing tools (e.g., newlines, HTML).
    # app_logger.info(f"Processing data from {user_id}: {user_input}") # <-- AVOID THIS PATTERN

    # BETTER (using substitution): Still logs potentially problematic chars,
    # but the logger handles them safely for *its* processing.
    app_logger.info("Processing data from %s: %s", user_id, user_input)

    # BEST (with optional sanitization if log viewing context requires it):
    # Sanitize potentially problematic input *before* logging, but STILL use parameter substitution.
    sanitized_input = sanitize_log_input(user_input)
    app_logger.info("Processing sanitized data from %s: %s", user_id, sanitized_input)

    # --- AVOIDING SENSITIVE DATA ---
    password = "user_secret_password"
    api_key = "sk_live_abcdefghijklmnopqrstuvwxyz"

    # BAD: Logging sensitive data directly
    # sensitive_logger.info(f"User {user_id} authenticated with password: {password}") # <-- NEVER DO THIS

    # GOOD: Avoid logging sensitive data entirely if possible.
    sensitive_logger.info("User %s authenticated successfully.", user_id)

    # ACCEPTABLE (if absolutely necessary): Mask sensitive data
    masked_api_key = f"{api_key[:8]}...{api_key[-4:]}" # Example masking
    sensitive_logger.warning("API key used by %s: %s", user_id, masked_api_key) # Log only masked version

    # --- LOGGING EXCEPTIONS ---
    try:
        result = 10 / 0
    except ZeroDivisionError:
        # Automatically includes traceback information
        app_logger.error("Calculation failed for user %s", user_id, exc_info=True)
        # Or using exception() shortcut which implies exc_info=True and logs at ERROR level
        # app_logger.exception("Calculation failed for user %s", user_id)

    # --- ADDING EXTRA CONTEXT ---
    request_id = "req-abc-123"
    session_id = "sess-xyz-789"
    # Use the 'extra' dictionary to add structured context
    app_logger.info(
        "Processing request for user %s",
        user_id,
        extra={"extra_data": {"request_id": request_id, "session_id": session_id}}
    )

    app_logger.info("Application finished.")