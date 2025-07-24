import re
import html
from typing import Optional, Union, List, Dict, Any
import ipaddress
import unicodedata


class InputValidator:
    """
    A utility class for securely validating various types of user input.
    Implements defense-in-depth approach for input validation.
    """
    
    @staticmethod
    def validate_string(input_str: str, 
                       min_length: int = 0,
                       max_length: int = 100,
                       pattern: Optional[str] = None,
                       sanitize: bool = True) -> Optional[str]:
        """
        Validates and optionally sanitizes a string input.
        
        Args:
            input_str: The string to validate
            min_length: Minimum acceptable length
            max_length: Maximum acceptable length
            pattern: Optional regex pattern the string must match
            sanitize: Whether to sanitize the input (escape HTML)
            
        Returns:
            Validated string or None if validation fails
        """
        if not isinstance(input_str, str):
            return None
            
        # Normalize Unicode to prevent homograph attacks
        input_str = unicodedata.normalize('NFKC', input_str)
        
        # Check length constraints
        if len(input_str) < min_length or len(input_str) > max_length:
            return None
            
        # Check pattern if provided
        if pattern and not re.fullmatch(pattern, input_str):
            return None
            
        # Sanitize if requested
        if sanitize:
            input_str = html.escape(input_str)
            
        return input_str
    
    @staticmethod
    def validate_integer(input_val: Any, 
                         min_value: Optional[int] = None,
                         max_value: Optional[int] = None) -> Optional[int]:
        """
        Validates an integer input within specified range.
        
        Args:
            input_val: The value to validate as integer
            min_value: Minimum acceptable value (inclusive)
            max_value: Maximum acceptable value (inclusive)
            
        Returns:
            Validated integer or None if validation fails
        """
        try:
            # Convert to integer and validate range
            int_val = int(input_val)
            
            if min_value is not None and int_val < min_value:
                return None
                
            if max_value is not None and int_val > max_value:
                return None
                
            return int_val
            
        except (ValueError, TypeError):
            return None
    
    @staticmethod
    def validate_email(email: str) -> Optional[str]:
        """
        Validates an email address.
        
        Args:
            email: The email address to validate
            
        Returns:
            Validated email or None if validation fails
        """
        # Basic pattern for email validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not isinstance(email, str):
            return None
            
        # Normalize
        email = unicodedata.normalize('NFKC', email.strip().lower())
        
        # Check pattern
        if not re.match(pattern, email):
            return None
            
        # Additional validation - no consecutive dots in local part
        local_part = email.split('@')[0]
        if '..' in local_part:
            return None
            
        return email
    
    @staticmethod
    def validate_ip_address(ip: str) -> Optional[str]:
        """
        Validates an IP address (IPv4 or IPv6).
        
        Args:
            ip: The IP address to validate
            
        Returns:
            Validated IP address or None if validation fails
        """
        try:
            # Using ipaddress module to validate
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            return None
    
    @staticmethod
    def validate_url(url: str, allowed_schemes: List[str] = None) -> Optional[str]:
        """
        Validates a URL with optional scheme restriction.
        
        Args:
            url: The URL to validate
            allowed_schemes: List of allowed schemes (e.g., ['http', 'https'])
            
        Returns:
            Validated URL or None if validation fails
        """
        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']
            
        if not isinstance(url, str):
            return None
            
        # Basic pattern for URL validation
        pattern = r'^(?:(?:' + '|'.join(allowed_schemes) + r')://)' + \
                  r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' + \
                  r'localhost|' + \
                  r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' + \
                  r'(?::\d+)?' + \
                  r'(?:/?|[/?]\S+)$'
        
        if not re.match(pattern, url, re.IGNORECASE):
            return None
            
        return url
    
    @staticmethod
    def validate_credit_card(card_number: str) -> Optional[str]:
        """
        Validates a credit card number using Luhn algorithm.
        
        Args:
            card_number: The credit card number to validate
            
        Returns:
            Validated card number or None if validation fails
        """
        if not isinstance(card_number, str):
            return None
            
        # Remove any non-digits
        digits = re.sub(r'\D', '', card_number)
        
        # Check length
        if len(digits) < 13 or len(digits) > 19:
            return None
            
        # Luhn algorithm implementation
        digits_sum = 0
        is_odd_position = True
        
        for digit in reversed(digits):
            digit_value = int(digit)
            
            if is_odd_position:
                digits_sum += digit_value
            else:
                doubled = digit_value * 2
                if doubled > 9:
                    doubled -= 9
                digits_sum += doubled
                
            is_odd_position = not is_odd_position
            
        return digits if digits_sum % 10 == 0 else None
    
    @staticmethod
    def sanitize_sql_input(input_str: str) -> str:
        """
        Sanitizes input for SQL queries.
        Note: This is not a substitute for prepared statements/parameterized queries!
        
        Args:
            input_str: The string to sanitize
            
        Returns:
            Sanitized string
        """
        if not isinstance(input_str, str):
            return ""
            
        # Replace quotes and other potentially dangerous characters
        sanitized = input_str.replace("'", "''")
        sanitized = sanitized.replace(";", "")
        sanitized = sanitized.replace("--", "")
        sanitized = sanitized.replace("/*", "")
        sanitized = sanitized.replace("*/", "")
        
        return sanitized


# Example usage
def example_usage():
    validator = InputValidator()
    
    # String validation
    username = validator.validate_string(
        input_str="JohnDoe123",
        min_length=3,
        max_length=20,
        pattern=r'^[a-zA-Z0-9]{3,20}$'
    )
    print(f"Username validation: {'Valid' if username else 'Invalid'}")
    
    # Integer validation
    age = validator.validate_integer(
        input_val="25",
        min_value=18,
        max_value=120
    )
    print(f"Age validation: {'Valid' if age else 'Invalid'}")
    
    # Email validation
    email = validator.validate_email("user@example.com")
    print(f"Email validation: {'Valid' if email else 'Invalid'}")
    
    # URL validation
    url = validator.validate_url("https://www.example.com/page")
    print(f"URL validation: {'Valid' if url else 'Invalid'}")
    
    # Credit card validation (example with a valid test number)
    card = validator.validate_credit_card("4111 1111 1111 1111")
    print(f"Credit card validation: {'Valid' if card else 'Invalid'}")


if __name__ == "__main__":
    example_usage()
