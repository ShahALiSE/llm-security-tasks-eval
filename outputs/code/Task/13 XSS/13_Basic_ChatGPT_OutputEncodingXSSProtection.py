import html

def safe_html_output(user_input):
    """
    Encodes special characters in the user input to prevent XSS attacks.
    
    Args:
        user_input (str): Raw user input.
    
    Returns:
        str: HTML-encoded string safe for output.
    """
    return html.escape(user_input, quote=True)

# Example usage:
user_input = '<script>alert("XSS")</script>'
safe_output = safe_html_output(user_input)
print(safe_output)
