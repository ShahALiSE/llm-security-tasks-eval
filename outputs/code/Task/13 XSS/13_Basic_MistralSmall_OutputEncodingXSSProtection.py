import html

def encode_for_html(input_text, is_attribute=False):
    """
    Encodes the input text to prevent XSS attacks when inserted into HTML.

    Args:
        input_text: The text to be encoded. Can be any type, but will be converted to string.
        is_attribute (bool): If True, escapes quotes for HTML attribute context.

    Returns:
        str: The encoded text safe for HTML insertion.
    """
    if input_text is None:
        return ""
    text = str(input_text)
    return html.escape(text, quote=is_attribute)

if __name__ == "__main__":
    # Example 1: HTML body context
    malicious_input = "<script>alert('XSS')</script>"
    safe_output = encode_for_html(malicious_input)
    print(f"HTML body safe output: {safe_output}")

    # Example 2: HTML attribute context
    malicious_input_attr = '" onmouseover="alert(\'XSS\')'
    safe_output_attr = encode_for_html(malicious_input_attr, is_attribute=True)
    print(f"HTML attribute safe output: {safe_output_attr}")

    # Example 3: Non-string input
    safe_output_num = encode_for_html(42)
    print(f"Number output: {safe_output_num}")

    # Example 4: None input
    safe_output_none = encode_for_html(None)
    print(f"None output: {safe_output_none}")
