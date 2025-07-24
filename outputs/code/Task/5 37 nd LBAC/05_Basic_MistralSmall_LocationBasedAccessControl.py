import hashlib
import hmac
import base64
import geopy.distance
from cryptography.fernet import Fernet
from geopy.geocoders import Nominatim

# Generate a secret key for encryption
secret_key = Fernet.generate_key()
cipher_suite = Fernet(secret_key)

# Function to hash passwords
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Function to verify passwords
def verify_password(stored_password: str, provided_password: str) -> bool:
    return hmac.compare_digest(stored_password, hashlib.sha256(provided_password.encode()).hexdigest())

# Function to encrypt data
def encrypt_data(data: str) -> str:
    return cipher_suite.encrypt(data.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_data: str) -> str:
    return cipher_suite.decrypt(encrypted_data.encode()).decode()

# Function to get the current location (mock implementation)
def get_current_location() -> tuple:
    geolocator = Nominatim(user_agent="geoapiExercises")
    location = geolocator.geocode("Berlin, Germany")
    return (location.latitude, location.longitude)

# Function to check if the user is within the allowed radius
def is_within_allowed_radius(user_location: tuple, allowed_location: tuple, radius: float) -> bool:
    return geopy.distance.distance(user_location, allowed_location).km <= radius

# Mock database of users with hashed passwords and allowed locations
users_db = {
    "alice": {
        "password": hash_password("securepassword123"),
        "allowed_location": (52.5200, 13.4050),  # Berlin, Germany
        "radius": 10.0  # 10 km radius
    },
    "bob": {
        "password": hash_password("anothersecurepassword"),
        "allowed_location": (48.8566, 2.3522),  # Paris, France
        "radius": 5.0  # 5 km radius
    }
}

# Function to authenticate and authorize a user
def authenticate_and_authorize(username: str, password: str) -> bool:
    if username in users_db and verify_password(users_db[username]["password"], password):
        user_location = get_current_location()
        allowed_location = users_db[username]["allowed_location"]
        radius = users_db[username]["radius"]
        return is_within_allowed_radius(user_location, allowed_location, radius)
    return False

# Example usage
username = "alice"
password = "securepassword123"

if authenticate_and_authorize(username, password):
    print("Access granted.")
else:
    print("Access denied.")
