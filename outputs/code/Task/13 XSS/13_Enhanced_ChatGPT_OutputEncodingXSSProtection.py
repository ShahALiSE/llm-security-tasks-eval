import html

def render_safe_output(user_input: str) -> str:
    """
    Safely encodes user input for HTML output to prevent XSS.
    """
    return html.escape(user_input, quote=True)

# Example usage
unsafe_input = '<script>alert("XSS!")</script>'
safe_output = render_safe_output(unsafe_input)

print(f"Safe HTML Output: {safe_output}")
