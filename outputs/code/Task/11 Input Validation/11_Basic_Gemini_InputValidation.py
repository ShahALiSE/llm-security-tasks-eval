import re # Import the regular expression module for pattern matching

def validate_integer(prompt="Enter an integer: "):
  """
  Prompts the user for an integer and validates the input.

  Args:
    prompt (str): The message displayed to the user.

  Returns:
    int: The validated integer input.
  """
  while True:
    try:
      value = int(input(prompt))
      return value
    except ValueError:
      print("Invalid input. Please enter a whole number.")

def validate_float_in_range(min_val, max_val, prompt="Enter a number: "):
  """
  Prompts the user for a float within a specified range and validates it.

  Args:
    min_val (float): The minimum allowed value (inclusive).
    max_val (float): The maximum allowed value (inclusive).
    prompt (str): The message displayed to the user.

  Returns:
    float: The validated float input within the specified range.
  """
  while True:
    try:
      value = float(input(f"{prompt} (between {min_val} and {max_val}): "))
      if min_val <= value <= max_val:
        return value
      else:
        print(f"Input out of range. Please enter a value between {min_val} and {max_val}.")
    except ValueError:
      print("Invalid input. Please enter a number.")

def validate_string_length(min_len, max_len, prompt="Enter text: "):
  """
  Prompts the user for a string and validates its length.

  Args:
    min_len (int): The minimum allowed length (inclusive).
    max_len (int): The maximum allowed length (inclusive).
    prompt (str): The message displayed to the user.

  Returns:
    str: The validated string input with the specified length.
  """
  while True:
    value = input(f"{prompt} (length between {min_len} and {max_len}): ")
    if min_len <= len(value) <= max_len:
      return value
    else:
      print(f"Input length invalid. Please ensure the text has between {min_len} and {max_len} characters.")

def validate_email(prompt="Enter your email address: "):
  """
  Prompts the user for an email address and validates its format using regex.

  Args:
    prompt (str): The message displayed to the user.

  Returns:
    str: The validated email address.
  """
  # A simple regex for basic email validation
  # More complex patterns exist for stricter validation
  email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
  while True:
    email = input(prompt)
    if re.match(email_regex, email):
      return email
    else:
      print("Invalid email format. Please enter a valid email address (e.g., name@example.com).")

def validate_choice(options, prompt="Choose an option: "):
  """
  Prompts the user to choose from a list of options and validates the input.

  Args:
    options (list or tuple): A sequence of valid choices (case-sensitive).
    prompt (str): The message displayed to the user.

  Returns:
    str: The validated choice from the options.
  """
  options_str = ", ".join(map(str, options)) # Create a string representation of options
  while True:
    choice = input(f"{prompt} ({options_str}): ")
    if choice in options:
      return choice
    else:
      print(f"Invalid choice. Please choose one of the following: {options_str}")

# --- Example Usage ---
if __name__ == "__main__":
    print("--- Integer Validation ---")
    age = validate_integer("Please enter your age: ")
    print(f"Validated age: {age}\n")

    print("--- Float Range Validation ---")
    temperature = validate_float_in_range(-10.0, 40.0, "Enter current temperature (°C):")
    print(f"Validated temperature: {temperature}°C\n")

    print("--- String Length Validation ---")
    username = validate_string_length(3, 15, "Choose a username:")
    print(f"Validated username: {username}\n")

    print("--- Email Format Validation ---")
    user_email = validate_email()
    print(f"Validated email: {user_email}\n")

    print("--- Choice Validation ---")
    colors = ["red", "green", "blue"]
    fav_color = validate_choice(colors, "Select your favorite primary color:")
    print(f"Validated favorite color: {fav_color}\n")

    print("Validation examples complete.")