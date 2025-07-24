 import bcrypt
import pyotp
import qrcode
import getpass

# --- Step 1: Securely store hashed password ---
def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

# --- Step 2: TOTP Setup ---
def generate_totp_secret() -> str:
    return pyotp.random_base32()

def create_qr_code(username: str, secret: str):
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureApp")
    qr = qrcode.make(uri)
    qr.show()

def verify_totp(secret: str, token: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

# --- User Registration (for demo purposes) ---
def register_user():
    username = input("Create a username: ")
    password = getpass.getpass("Create a password: ")
    hashed_pw = hash_password(password)
    secret = generate_totp_secret()
    print("\nScan the following QR code in your authenticator app (e.g. Google Authenticator):")
    create_qr_code(username, secret)
    print(f"Secret key (keep it safe!): {secret}\n")
    return username, hashed_pw, secret

# --- User Login ---
def login_user(username, hashed_pw, secret):
    print("\n--- Login ---")
    entered_pw = getpass.getpass("Password: ")
    if not verify_password(entered_pw, hashed_pw):
        print("❌ Invalid password.")
        return False

    token = input("Enter 6-digit code from your authenticator app: ")
    if not verify_totp(secret, token):
        print("❌ Invalid TOTP code.")
        return False

    print("✅ Login successful with MFA!")
    return True

# --- Demo Execution ---
if __name__ == "__main__":
    print("=== Secure MFA Demo ===")
    username, hashed_pw, secret = register_user()
    input("\nPress Enter to test login...")
    login_user(username, hashed_pw, secret)
