import html
import urllib.parse
import json
import re
from typing import Optional, Dict, Any


class OutputEncoder:
    """
    A comprehensive output encoder to prevent XSS attacks by properly encoding
    user input based on the output context (HTML, JavaScript, URL, CSS, etc.)
    """
    
    @staticmethod
    def html_encode(text: str) -> str:
        """
        Encode text for safe insertion into HTML content.
        Encodes: &, <, >, ", '
        """
        if not isinstance(text, str):
            text = str(text)
        return html.escape(text, quote=True)
    
    @staticmethod
    def html_attribute_encode(text: str) -> str:
        """
        Encode text for safe insertion into HTML attributes.
        More restrictive than html_encode for attribute contexts.
        """
        if not isinstance(text, str):
            text = str(text)
        
        # HTML escape first
        encoded = html.escape(text, quote=True)
        
        # Additional encoding for attribute context
        encoded = encoded.replace(' ', '&#x20;')
        encoded = encoded.replace('\t', '&#x09;')
        encoded = encoded.replace('\n', '&#x0A;')
        encoded = encoded.replace('\r', '&#x0D;')
        
        return encoded
    
    @staticmethod
    def javascript_encode(text: str) -> str:
        """
        Encode text for safe insertion into JavaScript strings.
        Handles various JavaScript escape sequences.
        """
        if not isinstance(text, str):
            text = str(text)
        
        # Use JSON encoding which is safe for JavaScript string contexts
        return json.dumps(text)[1:-1]  # Remove surrounding quotes
    
    @staticmethod
    def url_encode(text: str) -> str:
        """
        Encode text for safe insertion into URLs.
        """
        if not isinstance(text, str):
            text = str(text)
        return urllib.parse.quote(text, safe='')
    
    @staticmethod
    def css_encode(text: str) -> str:
        """
        Encode text for safe insertion into CSS values.
        """
        if not isinstance(text, str):
            text = str(text)
        
        # Encode all non-alphanumeric characters as hex escapes
        encoded = ""
        for char in text:
            if char.isalnum():
                encoded += char
            else:
                encoded += f"\\{ord(char):x} "
        
        return encoded.rstrip()
    
    @staticmethod
    def json_encode(data: Any) -> str:
        """
        Safely encode data as JSON for insertion into HTML.
        Prevents script injection in JSON embedded in HTML.
        """
        json_str = json.dumps(data, ensure_ascii=True)
        
        # Additional encoding to prevent script injection
        json_str = json_str.replace('<', '\\u003c')
        json_str = json_str.replace('>', '\\u003e')
        json_str = json_str.replace('&', '\\u0026')
        json_str = json_str.replace('\u2028', '\\u2028')  # Line separator
        json_str = json_str.replace('\u2029', '\\u2029')  # Paragraph separator
        
        return json_str


class SecureTemplateRenderer:
    """
    A secure template renderer that applies appropriate encoding based on context.
    """
    
    def __init__(self):
        self.encoder = OutputEncoder()
    
    def render_html_content(self, template: str, data: Dict[str, Any]) -> str:
        """
        Render template with HTML content encoding.
        """
        for key, value in data.items():
            placeholder = f"{{{key}}}"
            if placeholder in template:
                encoded_value = self.encoder.html_encode(str(value))
                template = template.replace(placeholder, encoded_value)
        return template
    
    def render_html_attribute(self, template: str, data: Dict[str, Any]) -> str:
        """
        Render template with HTML attribute encoding.
        """
        for key, value in data.items():
            placeholder = f"{{{key}}}"
            if placeholder in template:
                encoded_value = self.encoder.html_attribute_encode(str(value))
                template = template.replace(placeholder, encoded_value)
        return template
    
    def render_javascript(self, template: str, data: Dict[str, Any]) -> str:
        """
        Render template with JavaScript encoding.
        """
        for key, value in data.items():
            placeholder = f"{{{key}}}"
            if placeholder in template:
                encoded_value = self.encoder.javascript_encode(str(value))
                template = template.replace(placeholder, encoded_value)
        return template


def demonstrate_encoding():
    """
    Demonstrate various encoding techniques with potentially malicious input.
    """
    encoder = OutputEncoder()
    renderer = SecureTemplateRenderer()
    
    # Malicious input examples
    malicious_inputs = [
        "<script>alert('XSS')</script>",
        "'; DROP TABLE users; --",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "\" onmouseover=\"alert('XSS')\"",
        "</script><script>alert('XSS')</script>",
        "&lt;script&gt;alert('XSS')&lt;/script&gt;"
    ]
    
    print("=== XSS Prevention Output Encoding Demo ===\n")
    
    for i, malicious_input in enumerate(malicious_inputs, 1):
        print(f"Example {i}: {malicious_input}")
        print("-" * 50)
        
        # HTML Content Context
        html_encoded = encoder.html_encode(malicious_input)
        print(f"HTML Encoded: {html_encoded}")
        
        # HTML Attribute Context
        attr_encoded = encoder.html_attribute_encode(malicious_input)
        print(f"HTML Attribute Encoded: {attr_encoded}")
        
        # JavaScript Context
        js_encoded = encoder.javascript_encode(malicious_input)
        print(f"JavaScript Encoded: {js_encoded}")
        
        # URL Context
        url_encoded = encoder.url_encode(malicious_input)
        print(f"URL Encoded: {url_encoded}")
        
        # CSS Context
        css_encoded = encoder.css_encode(malicious_input)
        print(f"CSS Encoded: {css_encoded}")
        
        print("\n")
    
    # Template rendering examples
    print("=== Secure Template Rendering Examples ===\n")
    
    user_data = {
        "username": "<script>alert('XSS')</script>",
        "comment": "This is a 'test' comment with \"quotes\"",
        "url": "javascript:alert('XSS')"
    }
    
    # HTML content template
    html_template = "<div>Welcome, {username}!</div>"
    safe_html = renderer.render_html_content(html_template, user_data)
    print(f"HTML Template: {html_template}")
    print(f"Safe HTML: {safe_html}\n")
    
    # HTML attribute template
    attr_template = '<input type="text" value="{comment}" />'
    safe_attr = renderer.render_html_attribute(attr_template, user_data)
    print(f"Attribute Template: {attr_template}")
    print(f"Safe Attribute: {safe_attr}\n")
    
    # JavaScript template
    js_template = "var username = '{username}';"
    safe_js = renderer.render_javascript(js_template, user_data)
    print(f"JavaScript Template: {js_template}")
    print(f"Safe JavaScript: {safe_js}\n")
    
    # JSON encoding for HTML embedding
    json_data = {"user": user_data["username"], "id": 123}
    safe_json = encoder.json_encode(json_data)
    print(f"JSON for HTML: {safe_json}\n")


def validate_encoding_effectiveness():
    """
    Validate that encoding properly neutralizes XSS attempts.
    """
    encoder = OutputEncoder()
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg/onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')></iframe>"
    ]
    
    print("=== Encoding Validation ===\n")
    
    for payload in xss_payloads:
        encoded = encoder.html_encode(payload)
        
        # Check if dangerous patterns are neutralized
        dangerous_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', '<iframe']
        is_safe = not any(pattern.lower() in encoded.lower() for pattern in dangerous_patterns)
        
        print(f"Payload: {payload}")
        print(f"Encoded: {encoded}")
        print(f"Safe: {'✓' if is_safe else '✗'}")
        print("-" * 40)


if __name__ == "__main__":
    # Run demonstrations
    demonstrate_encoding()
    validate_encoding_effectiveness()
    
    print("=== Usage Recommendations ===")
    print("1. Always encode output based on the context where it will be used")
    print("2. HTML content: Use html_encode()")
    print("3. HTML attributes: Use html_attribute_encode()")
    print("4. JavaScript strings: Use javascript_encode()")
    print("5. URLs: Use url_encode()")
    print("6. CSS values: Use css_encode()")
    print("7. JSON in HTML: Use json_encode()")
    print("8. Never trust user input - always encode before output")
    print("9. Use Content Security Policy (CSP) as an additional layer")
    print("10. Consider using template engines with auto-escaping")
