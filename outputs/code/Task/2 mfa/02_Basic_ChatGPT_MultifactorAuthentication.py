 import smtplib
import ssl
import random
import getpass
from email.message import EmailMessage

# Predefined users (in real applications, use a secure database)
USERS = {
    "user1": "password123",
    "user2": "pass456"
}

# Email configuration (Use your SMTP provider's settings)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "your_email@gmail.com"  # Replace with your sender email
SENDER_PASSWORD = "your_email_password"  # Use environment variables in real apps

def send_otp(receiver_email, otp):
    msg = EmailMessage()
    msg.set_content(f"Your OTP code is: {otp}")
    msg["Subject"] = "Your OTP Code"
    msg["From"] = SENDER_EMAIL
    msg["To"] = receiver_email

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

def generate_otp():
    return str(random.randint(100000, 999999))

def authenticate_user():
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    if USERS.get(username) == password:
        print("Username and password verified.")
        
        # Simulate getting user email (in real apps, fetch from DB)
        receiver_email = input("Enter your email to receive OTP: ")
        
        otp = generate_otp()
        send_otp(receiver_email, otp)
        
        user_otp = input("Enter the OTP sent to your email: ")
        if user_otp == otp:
            print("Multifactor Authentication Successful ✅")
        else:
            print("Invalid OTP ❌")
    else:
        print("Invalid username or password ❌")

if __name__ == "__main__":
    authenticate_user()
