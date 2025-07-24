import html

def safe_output(data: any) -> str:
    """
    Encode untrusted data for safe HTML output.
    
    Converts special characters to HTML entities to prevent XSS attacks.
    Handles None and non-string types gracefully.
    
    Args:
        data: Input data (any type). Non-strings are converted to strings.
        
    Returns:
        Encoded string safe for HTML output.
    """
    if data is None:
        return ''
    if not isinstance(data, str):
        data = str(data)
    return html.escape(data, quote=True)

# Example usage
if __name__ == '__main__':
    user_input = '<script>alert("XSS Attack!");</script>'
    safe_html = safe_output(user_input)
    print("Original input:", user_input)
    print("Safe output:   ", safe_html)