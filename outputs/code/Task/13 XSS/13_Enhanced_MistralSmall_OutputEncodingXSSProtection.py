from markupsafe import escape
import bleach

def encode_for_html(user_input):
    """
    Encode user input for safe HTML output.

    Parameters:
    - user_input (str): The input string to be encoded.

    Returns:
    - str: The encoded string safe for HTML output.
    """
    return escape(user_input)

def sanitize_html(user_input, allowed_tags=None):
    """
    Sanitize user input allowing only specified HTML tags.

    Parameters:
    - user_input (str): The input string to be sanitized.
    - allowed_tags (list): List of allowed HTML tags. Defaults to empty list.

    Returns:
    - str: The sanitized string with only allowed HTML tags.
    """
    if allowed_tags is None:
        allowed_tags = []
    return bleach.clean(user_input, tags=allowed_tags)

if __name__ == "__main__":
    # Example 1: Encoding for HTML body
    user_input = "<script>alert('XSS Attack!')</script>"
    print("Encoded HTML:", encode_for_html(user_input))

    # Example 2: Sanitizing HTML with allowed tags
    user_input_with_safe_tags = "<b>Safe</b> <script>alert('XSS Attack!')</script>"
    print("Sanitized HTML:", sanitize_html(user_input_with_safe_tags, allowed_tags=['b']))
