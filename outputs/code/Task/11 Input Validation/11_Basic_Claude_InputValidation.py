"""
input_validation.py - A comprehensive input validation module

This module provides functions for validating different types of user inputs
such as strings, numbers, emails, phone numbers, dates, etc.
"""

import re
import datetime
from typing import Any, Union, Optional, Pattern, List, Dict, Tuple


def validate_string(
    value: str,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    allowed_chars: Optional[str] = None,
    regex_pattern: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Validates a string based on given parameters.
    
    Args:
        value: The string to validate
        min_length: Minimum allowed length
        max_length: Maximum allowed length
        allowed_chars: String containing all allowed characters
        regex_pattern: Regular expression pattern to match
        
    Returns:
        Tuple containing (is_valid: bool, error_message: str)
    """
    if not isinstance(value, str):
        return False, "Input must be a string"
    
    if min_length is not None and len(value) < min_length:
        return False, f"Input must be at least {min_length} characters long"
    
    if max_length is not None and len(value) > max_length:
        return False, f"Input must be at most {max_length} characters long"
    
    if allowed_chars is not None and not all(char in allowed_chars for char in value):
        return False, f"Input contains disallowed characters"
    
    if regex_pattern is not None and not re.match(regex_pattern, value):
        return False, f"Input format is invalid"
    
    return True, ""


def validate_number(
    value: Any,
    min_value: Optional[Union[int, float]] = None,
    max_value: Optional[Union[int, float]] = None,
    is_integer: bool = False
) -> Tuple[bool, str]:
    """
    Validates numerical input.
    
    Args:
        value: The value to validate
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        is_integer: Whether the value must be an integer
        
    Returns:
        Tuple containing (is_valid: bool, error_message: str)
    """
    # First check if it's a number
    try:
        if is_integer:
            if not isinstance(value, int) and not (isinstance(value, str) and value.isdigit()):
                return False, "Input must be an integer"
            num_value = int(value)
        else:
            num_value = float(value)
    except (ValueError, TypeError):
        return False, "Input must be a number"
    
    if min_value is not None and num_value < min_value:
        return False, f"Input must be greater than or equal to {min_value}"
    
    if max_value is not None and num_value > max_value:
        return False, f"Input must be less than or equal to {max_value}"
    
    return True, ""


def validate_email(value: str) -> Tuple[bool, str]:
    """
    Validates an email address.
    
    Args:
        value: The email address to validate
        
    Returns:
        Tuple containing (is_valid: bool, error_message: str)
    """
    # Basic email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not isinstance(value, str):
        return False, "Email must be a string"
    
    if not re.match(pattern, value):
        return False, "Invalid email format"
    
    return True, ""


def validate_phone_number(
    value: str,
    country_code: str = "US"
) -> Tuple[bool, str]:
    """
    Validates a phone number based on country format.
    
    Args:
        value: The phone number to validate
        country_code: Country code to determine validation rules
        
    Returns:
        Tuple containing (is_valid: bool, error_message: str)
    """
    # Remove common formatting characters
    cleaned_number = re.sub(r'[\s\-\(\)\.]', '', value)
    
    if country_code == "US":
        # US phone number validation (10 digits)
        pattern = r'^(\+?1)?[0-9]{10}$'
    elif country_code == "UK":
        # Basic UK phone number validation
        pattern = r'^(\+?44|0)[0-9]{10}$'
    else:
        # Generic international phone validation
        pattern = r'^\+?[0-9]{8,15}$'
    
    if not re.match(pattern, cleaned_number):
        return False, f"Invalid phone number format for {country_code}"
    
    return True, ""


def validate_date(
    value: str,
    format_str: str = "%Y-%m-%d",
    min_date: Optional[datetime.date] = None,
    max_date: Optional[datetime.date] = None
) -> Tuple[bool, str]:
    """
    Validates a date string.
    
    Args:
        value: The date string to validate
        format_str: Expected date format
        min_date: Minimum allowed date
        max_date: Maximum allowed date
        
    Returns:
        Tuple containing (is_valid: bool, error_message: str)
    """
    try:
        date_obj = datetime.datetime.strptime(value, format_str).date()
    except ValueError:
        return False, f"Invalid date format. Expected format: {format_str}"
    
    if min_date and date_obj < min_date:
        return False, f"Date must be on or after {min_date.strftime(format_str)}"
    
    if max_date and date_obj > max_date:
        return False, f"Date must be on or before {max_date.strftime(format_str)}"
    
    return True, ""


def validate_url(value: str) -> Tuple[bool, str]:
    """
    Validates a URL.
    
    Args:
        value: The URL to validate
        
    Returns:
        Tuple containing (is_valid: bool, error_message: str)
    """
    pattern = r'^(https?://)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(/.*)?$'
    
    if not isinstance(value, str):
        return False, "URL must be a string"
    
    if not re.match(pattern, value):
        return False, "Invalid URL format"
    
    return True, ""


def validate_password(
    value: str,
    min_length: int = 8,
    require_upper: bool = True,
    require_lower: bool = True,
    require_digit: bool = True,
    require_special: bool = True
) -> Tuple[bool, str]:
    """
    Validates a password.
    
    Args:
        value: The password to validate
        min_length: Minimum password length
        require_upper: Whether uppercase letters are required
        require_lower: Whether lowercase letters are required
        require_digit: Whether digits are required
        require_special: Whether special characters are required
        
    Returns:
        Tuple containing (is_valid: bool, error_message: str)
    """
    if len(value) < min_length:
        return False, f"Password must be at least {min_length} characters long"
    
    if require_upper and not any(c.isupper() for c in value):
        return False, "Password must contain at least one uppercase letter"
    
    if require_lower and not any(c.islower() for c in value):
        return False, "Password must contain at least one lowercase letter"
    
    if require_digit and not any(c.isdigit() for c in value):
        return False, "Password must contain at least one digit"
    
    if require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
        return False, "Password must contain at least one special character"
    
    return True, ""


def validate_choices(
    value: Any,
    choices: List[Any]
) -> Tuple[bool, str]:
    """
    Validates that a value is one of the allowed choices.
    
    Args:
        value: The value to validate
        choices: List of allowed values
        
    Returns:
        Tuple containing (is_valid: bool, error_message: str)
    """
    if value not in choices:
        return False, f"Input must be one of: {', '.join(str(c) for c in choices)}"
    
    return True, ""


def validate_credit_card(value: str) -> Tuple[bool, str]:
    """
    Validates a credit card number using the Luhn algorithm.
    
    Args:
        value: The credit card number to validate
        
    Returns:
        Tuple containing (is_valid: bool, error_message: str)
    """
    # Remove spaces and hyphens
    card_number = re.sub(r'[\s\-]', '', value)
    
    if not card_number.isdigit():
        return False, "Credit card number must contain only digits"
    
    if not 13 <= len(card_number) <= 19:
        return False, "Credit card number must be between 13 and 19 digits"
    
    # Luhn algorithm
    digits = [int(d) for d in card_number]
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:  # Odd position (0-indexed from right)
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    
    if checksum % 10 != 0:
        return False, "Invalid credit card number (checksum failed)"
    
    return True, ""


def validate_zip_code(
    value: str,
    country_code: str = "US"
) -> Tuple[bool, str]:
    """
    Validates a postal/zip code.
    
    Args:
        value: The postal code to validate
        country_code: Country code to determine validation rules
        
    Returns:
        Tuple containing (is_valid: bool, error_message: str)
    """
    patterns = {
        "US": r'^\d{5}(-\d{4})?$',        # US: 12345 or 12345-6789
        "CA": r'^[A-Za-z]\d[A-Za-z] \d[A-Za-z]\d$',  # Canada: A1A 1A1
        "UK": r'^[A-Z]{1,2}\d[A-Z\d]? \d[A-Z]{2}$',  # UK: AA1A 1AA or A1A 1AA
        # Add more countries as needed
    }
    
    if country_code not in patterns:
        return False, f"Validation for {country_code} postal codes not supported"
    
    if not re.match(patterns[country_code], value):
        return False, f"Invalid postal code format for {country_code}"
    
    return True, ""


def validate_form(
    form_data: Dict[str, Any],
    validation_rules: Dict[str, Dict[str, Any]]
) -> Dict[str, str]:
    """
    Validates multiple form fields according to specified rules.
    
    Args:
        form_data: Dictionary of field names and values
        validation_rules: Dictionary of field names and their validation parameters
        
    Returns:
        Dictionary of field names and error messages (empty if valid)
    """
    errors = {}
    
    for field_name, rules in validation_rules.items():
        # Skip validation if field is not required and empty
        if not rules.get('required', True) and (field_name not in form_data or form_data[field_name] == ''):
            continue
            
        # Check if required field is missing
        if rules.get('required', True) and (field_name not in form_data or form_data[field_name] == ''):
            errors[field_name] = "This field is required"
            continue
            
        # Get the field value
        value = form_data.get(field_name, '')
        
        # Validate based on field type
        validation_type = rules.get('type', 'string')
        is_valid = False
        error_msg = ""
        
        if validation_type == 'string':
            is_valid, error_msg = validate_string(
                value,
                min_length=rules.get('min_length'),
                max_length=rules.get('max_length'),
                allowed_chars=rules.get('allowed_chars'),
                regex_pattern=rules.get('pattern')
            )
        elif validation_type == 'number':
            is_valid, error_msg = validate_number(
                value,
                min_value=rules.get('min_value'),
                max_value=rules.get('max_value'),
                is_integer=rules.get('is_integer', False)
            )
        elif validation_type == 'email':
            is_valid, error_msg = validate_email(value)
        elif validation_type == 'phone':
            is_valid, error_msg = validate_phone_number(
                value,
                country_code=rules.get('country_code', 'US')
            )
        elif validation_type == 'date':
            is_valid, error_msg = validate_date(
                value,
                format_str=rules.get('format', '%Y-%m-%d'),
                min_date=rules.get('min_date'),
                max_date=rules.get('max_date')
            )
        elif validation_type == 'url':
            is_valid, error_msg = validate_url(value)
        elif validation_type == 'password':
            is_valid, error_msg = validate_password(
                value,
                min_length=rules.get('min_length', 8),
                require_upper=rules.get('require_upper', True),
                require_lower=rules.get('require_lower', True),
                require_digit=rules.get('require_digit', True),
                require_special=rules.get('require_special', True)
            )
        elif validation_type == 'choices':
            is_valid, error_msg = validate_choices(
                value,
                choices=rules.get('choices', [])
            )
        
        if not is_valid:
            errors[field_name] = error_msg
            
    return errors


# Example usage:
if __name__ == "__main__":
    # Example form validation
    form_data = {
        "username": "johndoe",
        "email": "john.doe@example.com",
        "age": "25",
        "password": "P@ssw0rd123",
        "country": "US"
    }
    
    validation_rules = {
        "username": {
            "type": "string",
            "min_length": 3,
            "max_length": 20,
            "pattern": r'^[a-zA-Z0-9_]+$'
        },
        "email": {
            "type": "email"
        },
        "age": {
            "type": "number",
            "min_value": 18,
            "max_value": 120,
            "is_integer": True
        },
        "password": {
            "type": "password",
            "min_length": 8
        },
        "country": {
            "type": "choices",
            "choices": ["US", "CA", "UK", "AU"]
        }
    }
    
    errors = validate_form(form_data, validation_rules)
    
    if errors:
        print("Validation errors:")
        for field, error in errors.items():
            print(f"- {field}: {error}")
    else:
        print("All data is valid!")
