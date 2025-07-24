import re
import os
from datetime import datetime
# For more robust email validation, install: pip install email-validator
try:
    from email_validator import validate_email, EmailNotValidError
    EMAIL_VALIDATOR_AVAILABLE = True
except ImportError:
    EMAIL_VALIDATOR_AVAILABLE = False
    print("Warning: 'email-validator' library not found. Falling back to basic regex for email validation.")
    print("Install with: pip install email-validator")

# --- Validation Functions ---

def validate_username(username: str, min_len: int = 3, max_len: int = 30) -> bool:
    """
    Validates a username.
    Allows alphanumeric characters and underscores.
    Checks length constraints.
    Uses allowlisting via regex.
    """
    if not isinstance(username, str):
        print("Validation Error: Username must be a string.")
        return False

    if not (min_len <= len(username) <= max_len):
        print(f"Validation Error: Username length must be between {min_len} and {max_len} characters.")
        return False

    # Regex: ^[a-zA-Z0-9_]+$
    # ^ - start of string anchor
    # [a-zA-Z0-9_] - allowed characters (alphanumeric + underscore)
    # + - one or more occurrences
    # $ - end of string anchor
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        print("Validation Error: Username contains invalid characters. Only alphanumeric and underscores are allowed.")
        return False

    return True

def validate_integer_input(input_str: str, min_val: int | None = None, max_val: int | None = None) -> int | None:
    """
    Validates if a string can be converted to an integer within an optional range.
    Returns the integer if valid, otherwise None.
    """
    if not isinstance(input_str, str):
         print("Validation Error: Input for integer conversion must be a string.")
         return None
    try:
        value = int(input_str.strip()) # strip whitespace before conversion
        if min_val is not None and value < min_val:
            print(f"Validation Error: Value must be at least {min_val}.")
            return None
        if max_val is not None and value > max_val:
            print(f"Validation Error: Value must be no more than {max_val}.")
            return None
        return value
    except ValueError:
        print("Validation Error: Input must be a valid integer.")
        return None

def validate_email_address(email_str: str) -> str | None:
    """
    Validates an email address.
    Uses the 'email-validator' library if available for robust checking (RFC compliant).
    Falls back to a basic regex if the library is not installed (less reliable).
    Returns the normalized email if valid, otherwise None.
    """
    if not isinstance(email_str, str):
        print("Validation Error: Email must be a string.")
        return False

    email_str = email_str.strip() # Basic canonicalization

    if EMAIL_VALIDATOR_AVAILABLE:
        try:
            # This library checks syntax, DNS records (optional), etc.
            email_info = validate_email(email_str, check_deliverability=False) # Set check_deliverability=True for MX record check
            return email_info.normalized # Use the normalized version
        except EmailNotValidError as e:
            print(f"Validation Error: Invalid email address: {e}")
            return None
    else:
        # Basic Regex (Not RFC compliant, misses many edge cases!)
        # Only use this as a fallback if the library is unavailable.
        # Allows: something@something.domain
        basic_email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(basic_email_regex, email_str):
            print("Validation Error: Email format appears invalid (basic check).")
            return None
        # Return the stripped string, as basic regex doesn't normalize complex cases
        return email_str


def validate_safestring_alphanumspace(input_str: str, max_len: int = 255) -> str | None:
    """
    Validates a string allowing only alphanumeric characters and spaces.
    Checks length. Good for names, titles, etc.
    Returns the validated string if ok, otherwise None.
    Uses allowlisting via regex.
    """
    if not isinstance(input_str, str):
        print("Validation Error: Input must be a string.")
        return None

    if len(input_str) > max_len:
         print(f"Validation Error: Input exceeds maximum length of {max_len}.")
         return None

    # Regex: ^[a-zA-Z0-9 ]+$
    # Allows letters, numbers, and spaces. Adjust if other chars like '-' or '.' are needed.
    if not re.match(r"^[a-zA-Z0-9 ]*$", input_str): # Use * for empty string allowed, + for non-empty
        print("Validation Error: Input contains invalid characters. Only alphanumeric and spaces are allowed.")
        return None

    return input_str # Return the original (already validated) string

def validate_choice(input_val: str, allowed_choices: list | set) -> str | None:
    """
    Validates if the input value is one of the allowed choices.
    Case-sensitive by default. Convert input/choices to same case if needed.
    """
    if input_val not in allowed_choices:
        print(f"Validation Error: Invalid choice. Allowed choices are: {', '.join(map(str, allowed_choices))}")
        return None
    return input_val


# --- Example Usage (Conceptual - Adapt to your framework like Flask/Django) ---

# Simulate receiving input (e.g., from a web form)
raw_user_input = {
    "username": "  GoodUser123 ",
    "age": " 42 ",
    "email": " test@example.com ",
    "status": "active",
    "comment": "This is a valid comment.",
    "bad_username": "Bad<script>alert('xss')</script>User",
    "bad_age": " twenty ",
    "bad_email": " not an email ",
    "bad_status": "invalid_option",
    "bad_comment": "Comment with disallowed chars $$$$",
}

print("--- Processing Valid Inputs ---")
validated_username = None
if "username" in raw_user_input:
    username_input = raw_user_input["username"].strip() # Basic canonicalization (remove leading/trailing whitespace)
    if validate_username(username_input):
        validated_username = username_input
        print(f"Username '{validated_username}' is valid.")

validated_age = None
if "age" in raw_user_input:
    age_input = raw_user_input["age"] # Keep as string for validator
    validated_age = validate_integer_input(age_input, min_val=0, max_val=130)
    if validated_age is not None:
        print(f"Age '{validated_age}' is valid.")

validated_email = None
if "email" in raw_user_input:
     email_input = raw_user_input["email"]
     validated_email = validate_email_address(email_input)
     if validated_email is not None:
        # Use the normalized email returned by the validator
        print(f"Email '{validated_email}' is valid.")

validated_status = None
if "status" in raw_user_input:
    status_input = raw_user_input["status"].strip().lower() # Canonicalize to lower case
    allowed_statuses = {"active", "inactive", "pending"}
    validated_status = validate_choice(status_input, allowed_statuses)
    if validated_status:
        print(f"Status '{validated_status}' is valid.")

validated_comment = None
if "comment" in raw_user_input:
    comment_input = raw_user_input["comment"] # Assume basic string
    validated_comment = validate_safestring_alphanumspace(comment_input, max_len=500)
    if validated_comment is not None:
        print(f"Comment '{validated_comment[:50]}...' is valid.")


print("\n--- Processing Invalid Inputs ---")
# These will print error messages from the validation functions

if "bad_username" in raw_user_input:
    print(f"\nValidating bad_username: '{raw_user_input['bad_username']}'")
    validate_username(raw_user_input["bad_username"].strip()) # Validation will fail

if "bad_age" in raw_user_input:
    print(f"\nValidating bad_age: '{raw_user_input['bad_age']}'")
    validate_integer_input(raw_user_input["bad_age"]) # Validation will fail

if "bad_email" in raw_user_input:
    print(f"\nValidating bad_email: '{raw_user_input['bad_email']}'")
    validate_email_address(raw_user_input["bad_email"]) # Validation will fail

if "bad_status" in raw_user_input:
    print(f"\nValidating bad_status: '{raw_user_input['bad_status']}'")
    validate_choice(raw_user_input["bad_status"].strip().lower(), {"active", "inactive", "pending"}) # Validation will fail

if "bad_comment" in raw_user_input:
    print(f"\nValidating bad_comment: '{raw_user_input['bad_comment']}'")
    validate_safestring_alphanumspace(raw_user_input["bad_comment"]) # Validation will fail


# --- Security Considerations Beyond Basic Validation ---

# 1. Output Encoding: When displaying validated user input back in HTML,
#    always encode it to prevent Cross-Site Scripting (XSS).
#    Frameworks like Flask (Jinja2) and Django do this automatically in templates.
#    Example (manual):
import html
potentially_unsafe_input = "<script>alert('XSS')</script>"
# Assume potentially_unsafe_input PASSED some validation (e.g., length check)
# but still contains HTML/JS. It MUST be encoded before display.
safe_html_output = html.escape(potentially_unsafe_input)
print(f"\nHTML Escaped Output: {safe_html_output}") # Output: &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;

# 2. Parameterized Queries (Database): When using input in database queries,
#    ALWAYS use parameterized queries or ORMs that handle this automatically.
#    This prevents SQL Injection.
#    NEVER build SQL queries using string formatting with raw user input.
#    Example (using sqlite3, concept applies to other DB drivers):
import sqlite3
conn = sqlite3.connect(':memory:') # Example in-memory DB
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, age INTEGER)")

# Assume validated_username and validated_age are available
# CORRECT - Parameterized Query:
try:
    cursor.execute("INSERT INTO users (username, age) VALUES (?, ?)", (validated_username, validated_age))
    conn.commit()
    print("\nUser inserted using parameterized query.")
except sqlite3.Error as e:
    print(f"\nDatabase Error: {e}")

# WRONG - Vulnerable to SQL Injection (DO NOT DO THIS):
# sql_string = f"INSERT INTO users (username, age) VALUES ('{validated_username}', {validated_age})"
# cursor.execute(sql_string) # Very dangerous!

conn.close()

# 3. Filesystem Access: Be extremely careful with input used in file paths.
#    Sanitize filenames, prevent directory traversal ('../'), check file types/sizes,
#    and ideally, store uploaded files with generated names outside the webroot.

# 4. Command Injection: Never pass raw user input directly to shell commands
#    (e.g., os.system, subprocess with shell=True). Use list-based arguments
#    for subprocess and validate/sanitize inputs rigorously.