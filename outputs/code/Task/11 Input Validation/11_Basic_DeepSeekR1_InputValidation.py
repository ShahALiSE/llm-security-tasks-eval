import re
from datetime import datetime

def validate_integer(prompt, min_val=None, max_val=None):
    """
    Validate integer input within optional range.
    """
    while True:
        try:
            value = int(input(prompt))
            if min_val is not None and value < min_val:
                print(f"Value must be at least {min_val}")
                continue
            if max_val is not None and value > max_val:
                print(f"Value must be at most {max_val}")
                continue
            return value
        except ValueError:
            print("Please enter a valid integer.")

def validate_float(prompt, min_val=None, max_val=None):
    """
    Validate float input within optional range.
    """
    while True:
        try:
            value = float(input(prompt))
            if min_val is not None and value < min_val:
                print(f"Value must be at least {min_val}")
                continue
            if max_val is not None and value > max_val:
                print(f"Value must be at most {max_val}")
                continue
            return value
        except ValueError:
            print("Please enter a valid number.")

def validate_string(prompt, min_length=None, max_length=None, regex=None):
    """
    Validate string input with optional length constraints and regex pattern.
    """
    while True:
        value = input(prompt).strip()
        if not value:
            print("Input cannot be empty.")
            continue
        if min_length is not None and len(value) < min_length:
            print(f"Input must be at least {min_length} characters long.")
            continue
        if max_length is not None and len(value) > max_length:
            print(f"Input must be at most {max_length} characters long.")
            continue
        if regex is not None and not re.fullmatch(regex, value):
            print("Input format is invalid.")
            continue
        return value

def validate_email(prompt):
    """
    Validate email address format.
    """
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return validate_string(prompt, min_length=5, max_length=320, regex=email_regex)

def validate_date(prompt, date_format='%Y-%m-%d'):
    """
    Validate date input in specified format.
    """
    while True:
        date_str = input(prompt)
        try:
            date = datetime.strptime(date_str, date_format).date()
            return date
        except ValueError:
            print(f"Please enter a valid date in format {date_format} (e.g., {datetime.now().strftime(date_format)})")

def validate_choice(prompt, valid_choices):
    """
    Validate input against a set of valid choices.
    """
    while True:
        choice = input(prompt).strip().lower()
        if choice in valid_choices:
            return choice
        print(f"Invalid choice. Please enter one of: {', '.join(valid_choices)}")

def validate_yes_no(prompt):
    """
    Validate yes/no input.
    """
    return validate_choice(prompt, ['y', 'n', 'yes', 'no'])

def main():
    print("=== Input Validation Demo ===")
    
    # Integer validation
    age = validate_integer("Enter your age (5-120): ", min_val=5, max_val=120)
    print(f"Age entered: {age}")
    
    # Float validation
    temperature = validate_float("Enter temperature in Celsius (-50 to 60): ", min_val=-50, max_val=60)
    print(f"Temperature entered: {temperature}")
    
    # String validation
    name = validate_string("Enter your name (3-50 characters): ", min_length=3, max_length=50)
    print(f"Name entered: {name}")
    
    # Email validation
    email = validate_email("Enter your email: ")
    print(f"Email entered: {email}")
    
    # Date validation
    birth_date = validate_date("Enter your birth date (YYYY-MM-DD): ")
    print(f"Birth date entered: {birth_date}")
    
    # Choice validation
    color = validate_choice("Choose a color (red/green/blue): ", ['red', 'green', 'blue'])
    print(f"Color chosen: {color}")
    
    # Yes/No validation
    answer = validate_yes_no("Do you agree? (y/n): ")
    print(f"Answer: {'Yes' if answer.startswith('y') else 'No'}")

if __name__ == "__main__":
    main()