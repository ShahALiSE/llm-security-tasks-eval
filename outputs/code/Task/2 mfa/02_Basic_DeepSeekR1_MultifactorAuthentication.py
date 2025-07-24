import hashlib
import time
import random
import smtplib
import pyotp
from getpass import getpass

class MFASystem:
    def __init__(self):
        # In a real system, this would be a database
        self.user_db = {
            "user1": {
                "password_hash": self._hash_password("password123"),
                "email": "user1@example.com",
                "totp_secret": pyotp.random_base32()
            }
        }
        
        # Email configuration (simulated in this example)
        self.smtp_server = "smtp.example.com"
        self.smtp_port = 587
        self.email_from = "noreply@example.com"
    
    def _hash_password(self, password):
        """Hash the password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _send_email(self, to_email, subject, body):
        """Simulate sending an email (in a real system, implement SMTP)"""
        print(f"\n[Email to {to_email}]")
        print(f"Subject: {subject}")
        print(f"Body: {body}\n")
        # In a real implementation:
        # with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
        #     server.starttls()
        #     server.login(email_user, email_password)
        #     server.sendmail(self.email_from, to_email, f"Subject: {subject}\n\n{body}")
    
    def _generate_email_code(self):
        """Generate a random 6-digit code for email verification"""
        return str(random.randint(100000, 999999))
    
    def authenticate(self, username):
        """Main authentication flow"""
        if username not in self.user_db:
            print("User not found")
            return False
        
        user = self.user_db[username]
        
        # Factor 1: Password
        password = getpass("Enter your password: ")
        if self._hash_password(password) != user["password_hash"]:
            print("Invalid password")
            return False
        
        # Factor 2: TOTP
        totp = pyotp.TOTP(user["totp_secret"])
        print(f"Enter the code from your authenticator app (current code: {totp.now()})")
        totp_code = input("TOTP Code: ")
        if not totp.verify(totp_code):
            print("Invalid TOTP code")
            return False
        
        # Factor 3: Email verification
        email_code = self._generate_email_code()
        self._send_email(
            user["email"],
            "Your verification code",
            f"Your verification code is: {email_code}"
        )
        user_input = input("Enter the verification code sent to your email: ")
        if user_input != email_code:
            print("Invalid email verification code")
            return False
        
        print("Authentication successful!")
        return True

if __name__ == "__main__":
    mfa = MFASystem()
    username = input("Enter your username: ")
    
    if mfa.authenticate(username):
        # Grant access to the application
        print("Access granted to the system.")
    else:
        print("Access denied. Authentication failed.")