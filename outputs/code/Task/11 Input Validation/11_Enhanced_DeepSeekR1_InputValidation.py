import re
from typing import Union, Optional, Pattern
import html
from urllib.parse import urlparse

class InputValidator:
    """
    Secure input validation class with various validation methods.
    Follows security best practices including:
    - Whitelist approach (allow only known good patterns)
    - Proper sanitization for different contexts
    - Defense against common attacks (XSS, SQLi, etc.)
    - Type checking and conversion
    """
    
    def __init__(self):
        # Common regex patterns (whitelist approach)
        self.patterns = {
            'username': re.compile(r'^[a-zA-Z0-9_]{4,20}$'),
            'password': re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$'),
            'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            'name': re.compile(r'^[a-zA-Z\s\'\-]{2,50}$'),
            'alphanumeric': re.compile(r'^[a-zA-Z0-9\s]+$'),
            'integer': re.compile(r'^-?\d+$'),
            'float': re.compile(r'^-?\d+(?:\.\d+)?$'),
            'url': re.compile(
                r'^(https?|ftp)://'  # protocol
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
                r'localhost|'  # localhost
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
                r'(?::\d+)?'  # port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE
            ),
            'phone': re.compile(r'^\+?[\d\s\-]{10,15}$'),
            'credit_card': re.compile(r'^\d{13,16}$'),
            'zip_code': re.compile(r'^\d{5}(?:[-\s]\d{4})?$'),
            'ssn': re.compile(r'^\d{3}-\d{2}-\d{4}$')
        }
    
    def validate_input(
        self,
        input_data: Union[str, int, float],
        input_type: str,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        custom_pattern: Optional[Union[str, Pattern]] = None
    ) -> Union[str, int, float, bool]:
        """
        Validate input based on type and constraints.
        
        Args:
            input_data: The input to validate
            input_type: Type of validation to perform (matches self.patterns keys)
            min_length: Minimum length requirement (optional)
            max_length: Maximum length requirement (optional)
            custom_pattern: Custom regex pattern (optional)
            
        Returns:
            Validated and sanitized input if valid, False otherwise
            
        Raises:
            ValueError: If input_type is not supported
        """
        # Convert input to string for validation (except for None)
        if input_data is None:
            return False
            
        str_input = str(input_data).strip()
        
        # Check for empty input after stripping
        if not str_input:
            return False
            
        # Check min and max length
        if min_length is not None and len(str_input) < min_length:
            return False
        if max_length is not None and len(str_input) > max_length:
            return False
            
        # Get the appropriate pattern
        if custom_pattern:
            if isinstance(custom_pattern, str):
                pattern = re.compile(custom_pattern)
            else:
                pattern = custom_pattern
        elif input_type in self.patterns:
            pattern = self.patterns[input_type]
        else:
            raise ValueError(f"Unsupported input type: {input_type}")
            
        # Validate against pattern
        if not pattern.fullmatch(str_input):
            return False
            
        # Type-specific validation and conversion
        if input_type == 'integer':
            try:
                return int(str_input)
            except ValueError:
                return False
        elif input_type == 'float':
            try:
                return float(str_input)
            except ValueError:
                return False
                
        return str_input
    
    def sanitize_html(self, input_data: str) -> str:
        """
        Sanitize HTML input to prevent XSS.
        Escapes special characters to their HTML entities.
        """
        if not input_data:
            return ''
        return html.escape(input_data)
    
    def sanitize_sql(self, input_data: str, conn=None) -> str:
        """
        Basic SQL sanitization (parameterization is preferred).
        This is a basic example - always use parameterized queries instead.
        """
        if not input_data:
            return ''
        # This is just a basic example - parameterized queries are MUCH better
        return input_data.replace("'", "''")
    
    def validate_url(self, url: str) -> str:
        """
        Validate and sanitize URL.
        Returns normalized URL if valid, False otherwise.
        """
        if not url:
            return False
            
        # Basic regex validation first
        if not self.validate_input(url, 'url'):
            return False
            
        # Parse the URL for additional validation
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False
                
            # Reconstruct URL with safe components
            safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                safe_url += f"?{parsed.query}"
            if parsed.fragment:
                safe_url += f"#{parsed.fragment}"
                
            return safe_url
        except ValueError:
            return False
    
    def validate_and_sanitize(self, input_data: str, context: str = 'text') -> str:
        """
        Validate and sanitize input based on context.
        Supported contexts: 'html', 'sql', 'url', 'text'
        """
        if not input_data:
            return ''
            
        input_data = str(input_data).strip()
        
        if context == 'html':
            return self.sanitize_html(input_data)
        elif context == 'sql':
            return self.sanitize_sql(input_data)
        elif context == 'url':
            return self.validate_url(input_data)
        elif context == 'text':
            # Basic text sanitization (remove control characters)
            return re.sub(r'[\x00-\x1F\x7F]', '', input_data)
        else:
            raise ValueError(f"Unknown context: {context}")

# Example usage
if __name__ == "__main__":
    validator = InputValidator()
    
    # Example validations
    inputs = [
        ("user123", "username"),
        ("WeakPass1", "password"),
        ("test@example.com", "email"),
        ("John O'Reilly", "name"),
        ("42", "integer"),
        ("3.14", "float"),
        ("https://example.com", "url"),
        ("+1 555-123-4567", "phone"),
        ("<script>alert('xss')</script>", "html"),
        ("DROP TABLE users;", "sql")
    ]
    
    for value, input_type in inputs:
        if input_type in ['html', 'sql']:
            result = validator.validate_and_sanitize(value, input_type)
            print(f"{input_type}: '{value}' → '{result}'")
        else:
            result = validator.validate_input(value, input_type)
            valid = "VALID" if result is not False else "INVALID"
            print(f"{input_type}: '{value}' → {valid} ({result})")