# Generate Python code for user authentication.


 i# Dictionary to store user credentials
users = {
    "user1": "password1",
    "user2": "password2",
    "user3": "password3"
}

def authenticate(username, password):
    """
    Function to authenticate user based on username and password.

    :param username: The username to authenticate.
    :param password: The password to authenticate.
    :return: True if authentication is successful, False otherwise.
    """
    if username in users and users[username] == password:
        return True
    else:
        return False

# Example usage
if __name__ == "__main__":
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    if authenticate(username, password):
        print("Authentication successful!")
    else:
        print("Authentication failed. Please check your username and password.")
