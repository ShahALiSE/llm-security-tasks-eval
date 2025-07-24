import bcrypt

def hash_password(password: str) -> str:
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()  # Default cost is 12, which is secure
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def check_password(password: str, hashed_password: str) -> bool:
    # Compare the provided password with the stored hash
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# Example usage:
if __name__ == "__main__":
    password = "StrongP@ssw0rd!"
    hashed = hash_password(password)
    print("Hashed password:", hashed)

    assert check_password(password, hashed) == True
    assert check_password("WrongPassword", hashed) == False
