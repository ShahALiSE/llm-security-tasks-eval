"""
XSS Prevention: Output Encoding Security Module
Comprehensive output encoding utilities to prevent Cross-Site Scripting attacks
"""

import html
import json
import re
import urllib.parse
from typing import Any, Dict, Optional, Union
from markupsafe import Markup, escape as markupsafe_escape


class OutputEncoder:
    """
    Secure output encoder for preventing XSS attacks across different contexts.
    Implements OWASP recommendations for output encoding.
    """
    
    @staticmethod
    def html_encode(data: Any) -> str:
        """
        HTML entity encoding for HTML content context.
        Encodes: & < > " ' 
        """
        if data is None:
            return ''
        
        text = str(data)
        # Use Python's built-in html.escape for basic encoding
        return html.escape(text, quote=True)
    
    @staticmethod
    def html_attribute_encode(data: Any) -> str:
        """
        Enhanced encoding for HTML attribute context.
        More restrictive than basic HTML encoding.
        """
        if data is None:
            return ''
            
        text = str(data)
        # Encode all non-alphanumeric characters except safe ones
        encoded = ''
        for char in text:
            if char.isalnum() or char in '-_.':
                encoded += char
            else:
                # Use numeric character reference
                encoded += f'&#x{ord(char):x};'
        return encoded
    
    @staticmethod
    def javascript_encode(data: Any) -> str:
        """
        JavaScript string encoding for embedding data in JS contexts.
        Encodes characters that could break out of JS strings.
        """
        if data is None:
            return ''
            
        text = str(data)
        # JavaScript encoding mapping
        js_escape_map = {
            '\\': '\\\\',
            '"': '\\"',
            "'": "\\'",
            '\n': '\\n',
            '\r': '\\r',
            '\t': '\\t',
            '\b': '\\b',
            '\f': '\\f',
            '/': '\\/',
            '<': '\\u003C',  # Prevent </script> attacks
            '>': '\\u003E',
            '&': '\\u0026',
            '=': '\\u003D',
            '\u2028': '\\u2028',  # Line separator
            '\u2029': '\\u2029',  # Paragraph separator
        }
        
        encoded = ''
        for char in text:
            if char in js_escape_map:
                encoded += js_escape_map[char]
            elif ord(char) < 32 or ord(char) > 126:
                # Encode non-printable and non-ASCII as unicode escapes
                encoded += f'\\u{ord(char):04X}'
            else:
                encoded += char
        
        return encoded
    
    @staticmethod
    def json_encode(data: Any) -> str:
        """
        Safe JSON encoding that prevents XSS in JSON contexts.
        """
        # Use json.dumps with ensure_ascii=True to escape unicode
        json_str = json.dumps(data, ensure_ascii=True, separators=(',', ':'))
        
        # Additional XSS protection for JSON in HTML contexts
        json_str = json_str.replace('<', '\\u003C')
        json_str = json_str.replace('>', '\\u003E')
        json_str = json_str.replace('&', '\\u0026')
        json_str = json_str.replace('\u2028', '\\u2028')
        json_str = json_str.replace('\u2029', '\\u2029')
        
        return json_str
    
    @staticmethod
    def url_encode(data: Any) -> str:
        """
        URL encoding for data in URL contexts.
        """
        if data is None:
            return ''
            
        text = str(data)
        return urllib.parse.quote(text, safe='')
    
    @staticmethod
    def css_encode(data: Any) -> str:
        """
        CSS encoding for data in CSS contexts.
        Encodes characters that could break CSS syntax.
        """
        if data is None:
            return ''
            
        text = str(data)
        encoded = ''
        
        for char in text:
            if char.isalnum():
                encoded += char
            else:
                # CSS hex encoding
                encoded += f'\\{ord(char):X} '
        
        return encoded.rstrip()


class SecureTemplateRenderer:
    """
    Template renderer with automatic context-aware encoding.
    """
    
    def __init__(self):
        self.encoder = OutputEncoder()
    
    def render_html_template(self, template: str, context: Dict[str, Any]) -> str:
        """
        Render HTML template with automatic XSS protection.
        Uses different encoding strategies based on context markers.
        """
        result = template
        
        for key, value in context.items():
            # HTML content context
            html_placeholder = f"{{{{ {key} }}}}"
            if html_placeholder in result:
                encoded_value = self.encoder.html_encode(value)
                result = result.replace(html_placeholder, encoded_value)
            
            # HTML attribute context
            attr_placeholder = f"{{{{ {key}|attr }}}}"
            if attr_placeholder in result:
                encoded_value = self.encoder.html_attribute_encode(value)
                result = result.replace(attr_placeholder, encoded_value)
            
            # JavaScript context
            js_placeholder = f"{{{{ {key}|js }}}}"
            if js_placeholder in result:
                encoded_value = self.encoder.javascript_encode(value)
                result = result.replace(js_placeholder, encoded_value)
            
            # JSON context
            json_placeholder = f"{{{{ {key}|json }}}}"
            if json_placeholder in result:
                encoded_value = self.encoder.json_encode(value)
                result = result.replace(json_placeholder, encoded_value)
            
            # URL context
            url_placeholder = f"{{{{ {key}|url }}}}"
            if url_placeholder in result:
                encoded_value = self.encoder.url_encode(value)
                result = result.replace(url_placeholder, encoded_value)
            
            # CSS context
            css_placeholder = f"{{{{ {key}|css }}}}"
            if css_placeholder in result:
                encoded_value = self.encoder.css_encode(value)
                result = result.replace(css_placeholder, encoded_value)
        
        return result


def validate_and_sanitize_input(user_input: str, max_length: int = 1000) -> str:
    """
    Input validation and sanitization as first line of defense.
    Note: This is NOT a replacement for output encoding!
    """
    if not isinstance(user_input, str):
        raise ValueError("Input must be a string")
    
    # Length validation
    if len(user_input) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")
    
    # Remove null bytes
    sanitized = user_input.replace('\x00', '')
    
    # Basic suspicious pattern detection (not comprehensive!)
    suspicious_patterns = [
        r'<script[^>]*>',
        r'javascript:',
        r'vbscript:',
        r'onload\s*=',
        r'onerror\s*=',
        r'onclick\s*=',
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, sanitized, re.IGNORECASE):
            raise ValueError("Input contains potentially malicious content")
    
    return sanitized


# Flask integration example
class FlaskXSSProtection:
    """
    Flask integration for automatic XSS protection.
    """
    
    @staticmethod
    def init_app(app):
        """Initialize Flask app with XSS protection."""
        encoder = OutputEncoder()
        
        # Add custom template filters
        app.jinja_env.filters['html_encode'] = encoder.html_encode
        app.jinja_env.filters['attr_encode'] = encoder.html_attribute_encode
        app.jinja_env.filters['js_encode'] = encoder.javascript_encode
        app.jinja_env.filters['json_encode'] = encoder.json_encode
        app.jinja_env.filters['url_encode'] = encoder.url_encode
        app.jinja_env.filters['css_encode'] = encoder.css_encode
        
        # Enable auto-escaping globally
        app.jinja_env.autoescape = True
        
        return encoder


# Django integration example
def django_context_processors(request):
    """
    Django context processor to add encoding functions.
    """
    encoder = OutputEncoder()
    return {
        'html_encode': encoder.html_encode,
        'attr_encode': encoder.html_attribute_encode,
        'js_encode': encoder.javascript_encode,
        'json_encode': encoder.json_encode,
        'url_encode': encoder.url_encode,
        'css_encode': encoder.css_encode,
    }


# Example usage and testing
def demonstration():
    """
    Demonstrate various encoding scenarios.
    """
    encoder = OutputEncoder()
    renderer = SecureTemplateRenderer()
    
    # Test data with XSS payloads
    malicious_inputs = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        "'; alert('XSS'); //",
        'javascript:alert("XSS")',
        '<img src="x" onerror="alert(\'XSS\')">',
        '\u003cscript\u003ealert("XSS")\u003c/script\u003e',
    ]
    
    print("=== XSS Prevention Demonstration ===\n")
    
    for payload in malicious_inputs:
        print(f"Original: {payload}")
        print(f"HTML Encoded: {encoder.html_encode(payload)}")
        print(f"Attribute Encoded: {encoder.html_attribute_encode(payload)}")
        print(f"JavaScript Encoded: {encoder.javascript_encode(payload)}")
        print(f"JSON Encoded: {encoder.json_encode(payload)}")
        print(f"URL Encoded: {encoder.url_encode(payload)}")
        print("-" * 50)
    
    # Template rendering example
    template = """
    <html>
        <body>
            <h1>{{ title }}</h1>
            <p>{{ content }}</p>
            <input type="text" value="{{ user_input|attr }}" />
            <script>
                var userData = "{{ user_data|js }}";
                var config = {{ app_config|json }};
            </script>
            <a href="/search?q={{ search_term|url }}">Search</a>
        </body>
    </html>
    """
    
    context = {
        'title': '<script>alert("Title XSS")</script>',
        'content': 'Normal content with <em>HTML</em>',
        'user_input': '"><script>alert("Input XSS")</script>',
        'user_data': 'User\'s "data" with\nnewlines',
        'app_config': {'debug': True, 'version': '1.0'},
        'search_term': 'search & destroy'
    }
    
    print("\n=== Template Rendering Example ===")
    rendered = renderer.render_html_template(template, context)
    print(rendered)


# Security best practices documentation
SECURITY_BEST_PRACTICES = """
XSS Prevention Best Practices:

1. ALWAYS use context-appropriate output encoding
   - HTML context: HTML entity encoding
   - HTML attributes: Attribute encoding
   - JavaScript: JavaScript string encoding
   - JSON: Safe JSON encoding with XSS protection
   - URLs: URL encoding
   - CSS: CSS encoding

2. Input validation is NOT sufficient alone
   - Always combine with output encoding
   - Validate input format, length, and content
   - Reject rather than sanitize when possible

3. Use security headers:
   - Content-Security-Policy (CSP)
   - X-XSS-Protection
   - X-Content-Type-Options

4. Framework-specific protections:
   - Enable auto-escaping in templates
   - Use framework's built-in encoding functions
   - Avoid innerHTML, use textContent

5. Regular security testing:
   - Automated XSS scanning
   - Manual penetration testing
   - Code review for XSS vulnerabilities

6. Content Security Policy example:
   Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
"""


if __name__ == "__main__":
    # Run demonstration
    demonstration()
    
    # Print security guidelines
    print("\n" + SECURITY_BEST_PRACTICES)