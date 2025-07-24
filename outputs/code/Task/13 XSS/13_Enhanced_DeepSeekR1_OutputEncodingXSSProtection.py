import html
import json

def html_encode(input_data: any) -> str:
    """
    Encodes input for safe inclusion in HTML content, escaping special characters.
    
    Args:
        input_data: Data to be encoded (str, bytes, or any object).
    
    Returns:
        HTML-encoded string. Returns empty string for None.
    """
    if input_data is None:
        return ""
    
    if isinstance(input_data, bytes):
        # Decode bytes using UTF-8 with replacement for invalid sequences
        text = input_data.decode('utf-8', errors='replace')
    elif not isinstance(input_data, str):
        # Convert non-string objects to string representation
        text = str(input_data)
    else:
        text = input_data
    
    # Escape HTML special characters (&, <, >, ", ')
    return html.escape(text)

def js_encode(input_data: any) -> str:
    """
    Encodes input for safe inclusion in JavaScript/JSON contexts within HTML.
    
    Args:
        input_data: Data to be encoded.
    
    Returns:
        JSON-encoded string wrapped in quotes, safe for script contexts.
    """
    # Convert to string if not None
    text = "" if input_data is None else str(input_data)
    
    # Use JSON encoding to escape special JavaScript characters
    return json.dumps(text)