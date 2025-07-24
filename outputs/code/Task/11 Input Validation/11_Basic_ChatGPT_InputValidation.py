import re

def validate_integer(prompt, min_value=None, max_value=None):
    while True:
        try:
            value = int(input(prompt))
            if (min_value is not None and value < min_value) or \
               (max_value is not None and value > max_value):
                print(f"Please enter a number between {min_value} and {max_value}.")
                continue
            return value
        except ValueError:
            print("Invalid input. Please enter an integer.")

def validate_float(prompt, min_value=None, max_value=None):
    while True:
        try:
            value = float(input(prompt))
            if (min_value is not None and value < min_value) or \
               (max_value is not None and value > max_value):
                print(f"Please enter a number between {min_value} and {max_value}.")
                continue
            return value
        except ValueError:
            print("Invalid input. Please enter a float.")

def validate_string(prompt, pattern=None, error_msg="Invalid format."):
    while True:
        value = input(prompt).strip()
        if pattern:
            if not re.fullmatch(pattern, value):
                print(error_msg)
                continue
        if value:
            return value
        print("Input cannot be empty.")

def validate_email(prompt):
    pattern = r"[^@]+@[^@]+\.[^@]+"
    return validate_string(prompt, pattern, "Invalid email format.")

# Example usage
if __name__ == "__main__":
    age = validate_integer("Enter your age: ", 1, 120)
    salary = validate_float("Enter your salary: ", 0)
    name = validate_string("Enter your name: ")
    email = validate_email("Enter your email: ")

    print("\nValidated Input:")
    print(f"Name: {name}")
    print(f"Age: {age}")
    print(f"Salary: {salary}")
    print(f"Email: {email}")
