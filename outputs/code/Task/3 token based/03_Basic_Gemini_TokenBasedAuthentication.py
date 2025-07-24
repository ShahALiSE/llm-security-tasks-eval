# Prompt : Generate Python code for Token-Based Authentication. 


import jwt
import time
import datetime
from datetime import timezone # Required for FastAPI example style

# --- Configuration (Keep your secret key secure!) ---
JWT_SECRET = "your-very-secret-key-keep-it-safe" # Use a strong, environment-specific secret
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Generating a Token (e.g., after successful login) ---
def create_access_token(data: dict, expires_delta: datetime.timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(timezone.utc) + expires_delta
    else:
        # Default expiration time
        expire = datetime.datetime.now(timezone.utc) + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": datetime.datetime.now(timezone.utc)}) # Add expiration and issued-at times
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

# --- Verifying a Token (e.g., in a middleware or decorator) ---
def verify_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        # You can add more checks here, e.g., check if user exists based on payload['sub']
        user_id = payload.get("sub") # 'sub' (subject) is a standard claim often used for user ID
        if user_id is None:
            print("Token verification failed: Subject (user ID) not found in token payload.")
            return None
        # Optionally check if token is expired (decode handles 'exp' claim)
        return payload # Return payload if valid
    except jwt.ExpiredSignatureError:
        print("Token verification failed: Token has expired.")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Token verification failed: Invalid token - {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during token verification: {e}")
        return None


# --- Example Usage ---

# Simulate successful login for user 'user123'
user_id_to_encode = "user123"
token_data = {"sub": user_id_to_encode} # Using 'sub' for subject/user identifier

# Create token
access_token = create_access_token(data=token_data)
print(f"Generated Token: {access_token}\n")

# Simulate receiving the token in a request and verifying it
received_token = access_token
decoded_payload = verify_token(received_token)

if decoded_payload:
    print("Token is valid.")
    print(f"Decoded Payload: {decoded_payload}")
    # Proceed with granting access to the resource
else:
    print("Token is invalid or expired.")
    # Deny access

# Example with an expired token
expired_token_payload = {"sub": "user456", "exp": datetime.datetime.now(timezone.utc) - datetime.timedelta(minutes=1)}
expired_token = jwt.encode(expired_token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
print(f"\nVerifying expired token: {expired_token}")
verify_token(expired_token)

# Example with an invalid signature (tampered token)
tampered_token = access_token[:-5] + "abcde" # Change last few chars
print(f"\nVerifying tampered token: {tampered_token}")
verify_token(tampered_token)