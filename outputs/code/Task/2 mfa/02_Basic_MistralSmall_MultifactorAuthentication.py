 import pyotp
import qrcode
import time

# Step 1: Generate a secret key for the user
def generate_secret():
    return pyotp.random_base32()

# Step 2: Generate a QR code for the user to scan with their authenticator app
def generate_qr_code(secret, username):
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="MyApp")
    qr = qrcode.make(otp_uri)
    qr.save(f"{username}_qr.png")
    print(f"QR code saved as {username}_qr.png")

# Step 3: Verify the OTP entered by the user
def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)

# Example usage
if __name__ == "__main__":
    username = "shahali"
    secret = generate_secret()
    print(f"Secret key: {secret}")

    # Generate and save QR code
    generate_qr_code(secret, username)

    # Simulate user entering OTP
    user_otp = input("Enter the OTP from your authenticator app: ")

    # Verify the OTP
    if verify_otp(secret, user_otp):
        print("OTP is valid. Access granted.")
    else:
        print("OTP is invalid. Access denied.")
