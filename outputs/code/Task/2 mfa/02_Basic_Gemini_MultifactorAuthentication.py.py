import pyotp
import qrcode
import time
import os

# In a real application, this would be a secure database.
# For this example, we'll use a simple dictionary to store user data.
# The structure is: { 'username': {'password': 'hashed_password', 'secret_key': 'user_secret_key'} }
user_database = {}

def generate_secret_key():
    """Generates a new Base32 secret key."""
    return pyotp.random_base32()

def generate_qr_code(username, secret_key):
    """Generates a QR code for the user to scan."""
    totp = pyotp.TOTP(secret_key)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name="MyApp")
    
    img = qrcode.make(provisioning_uri)
    qr_code_path = f"{username}_qr.png"
    img.save(qr_code_path)
    return qr_code_path

def register_user():
    """Registers a new user and sets up MFA."""
    print("\n--- New User Registration ---")
    username = input("Enter a new username: ")

    if username in user_database:
        print("Username already exists. Please choose another one.")
        return

    password = input("Enter a password: ")
    
    # In a real application, hash the password before storing.
    # For simplicity, we are storing it in plaintext.
    secret_key = generate_secret_key()
    user_database[username] = {
        'password': password,
        'secret_key': secret_key
    }

    qr_code_path = generate_qr_code(username, secret_key)
    print(f"\nUser '{username}' registered successfully!")
    print("Please scan the following QR code with your authenticator app (e.g., Google Authenticator).")
    print(f"QR code saved to: {qr_code_path}")
    print("This QR code will be deleted after you confirm setup.")
    
    # Display the QR code for a short period (in a real app, handle this securely)
    try:
        if os.name == 'nt': # For Windows
            os.startfile(qr_code_path)
        elif os.name == 'posix': # For macOS and Linux
            os.system(f'open {qr_code_path}')
    except Exception as e:
        print(f"\nCould not automatically open the QR code. Please open the file '{qr_code_path}' manually.")

    input("\nPress Enter after you have scanned the QR code...")
    
    # For security, delete the QR code file after setup
    try:
        os.remove(qr_code_path)
        print("QR code file has been deleted.")
    except OSError as e:
        print(f"Error deleting QR code file: {e}")

def login_user():
    """Logs in a user with their password and a TOTP."""
    print("\n--- User Login ---")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    user_data = user_database.get(username)

    # In a real application, compare hashed passwords.
    if user_data and user_data['password'] == password:
        print("\nPassword correct. Please provide your MFA code.")
        
        totp_code = input("Enter the 6-digit code from your authenticator app: ")
        
        totp = pyotp.TOTP(user_data['secret_key'])

        if totp.verify(totp_code):
            print("\nLogin successful! Welcome.")
            return True
        else:
            print("\nInvalid MFA code. Login failed.")
            return False
    else:
        print("\nInvalid username or password.")
        return False

def main():
    """Main function to run the application."""
    while True:
        print("\nWhat would you like to do?")
        print("1. Register a new user")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            register_user()
        elif choice == '2':
            login_user()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()