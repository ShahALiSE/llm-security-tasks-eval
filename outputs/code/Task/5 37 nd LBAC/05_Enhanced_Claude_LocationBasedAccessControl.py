import os
import time
import logging
import ipaddress
import requests
import hmac
import hashlib
import base64
import json
from functools import wraps
from typing import Dict, List, Tuple, Optional, Callable, Any
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, request, jsonify, g

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("lbac.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("LBAC")

# Initialize Flask app
app = Flask(__name__)

# Load secrets from environment variables (never hardcode these)
API_KEY = os.getenv("LOCATION_API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")
if not API_KEY or not SECRET_KEY:
    raise EnvironmentError("Required environment variables LOCATION_API_KEY and/or SECRET_KEY are not set")

# Generate encryption key from secret key
def get_encryption_key(secret_key: str) -> bytes:
    """Derive a Fernet encryption key from the secret key."""
    key = hashlib.sha256(secret_key.encode()).digest()
    return base64.urlsafe_b64encode(key)

# Initialize encryption
encryption_key = get_encryption_key(SECRET_KEY)
cipher_suite = Fernet(encryption_key)

# Allowed location regions (coordinates with radius in kilometers)
# Format: {"name": (latitude, longitude, radius_km)}
ALLOWED_REGIONS = {
    "headquarters": (37.7749, -122.4194, 1.0),  # Example: San Francisco
    "branch_office": (40.7128, -74.0060, 0.5),  # Example: New York
    "data_center": (47.6062, -122.3321, 0.3)    # Example: Seattle
}

# Access permission levels
PERMISSION_LEVELS = {
    "admin": ["headquarters", "branch_office", "data_center"],
    "manager": ["headquarters", "branch_office"],
    "staff": ["branch_office"],
    "contractor": ["data_center"]
}

# IP address restrictions (whitelist approach)
ALLOWED_IP_RANGES = [
    "10.0.0.0/8",      # Internal network
    "172.16.0.0/12",   # VPN network
    "192.168.0.0/16"   # Office network
]

# Cache for location data to prevent excessive API calls
location_cache = {}
CACHE_EXPIRY = 60 * 30  # 30 minutes in seconds

# Rate limiting configuration
RATE_LIMIT = {
    "window_seconds": 60,
    "max_requests": 10
}
rate_limit_store = {}  # {ip_address: (request_count, first_request_time)}

def encrypt_data(data: str) -> str:
    """Encrypt sensitive data."""
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data."""
    return cipher_suite.decrypt(encrypted_data.encode()).decode()

def generate_hmac(data: Dict[str, Any], secret: str) -> str:
    """Generate HMAC for data integrity verification."""
    message = json.dumps(data, sort_keys=True).encode()
    digest = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return digest

def verify_hmac(data: Dict[str, Any], signature: str, secret: str) -> bool:
    """Verify HMAC signature to ensure data hasn't been tampered with."""
    expected_signature = generate_hmac(data, secret)
    return hmac.compare_digest(signature, expected_signature)

def is_ip_allowed(ip_address: str) -> bool:
    """Check if an IP address is within allowed ranges."""
    try:
        ip = ipaddress.ip_address(ip_address)
        return any(ip in ipaddress.ip_network(allowed_range) 
                   for allowed_range in ALLOWED_IP_RANGES)
    except ValueError:
        logger.warning(f"Invalid IP address format: {ip_address}")
        return False

def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate distance between two geographic points using the Haversine formula.
    Returns distance in kilometers.
    """
    from math import radians, sin, cos, sqrt, atan2
    
    # Earth radius in kilometers
    R = 6371.0
    
    # Convert coordinates to radians
    lat1_rad = radians(lat1)
    lon1_rad = radians(lon1)
    lat2_rad = radians(lat2)
    lon2_rad = radians(lon2)
    
    # Difference in coordinates
    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad
    
    # Haversine formula
    a = sin(dlat / 2)**2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    distance = R * c
    
    return distance

def get_location_from_ip(ip_address: str) -> Optional[Tuple[float, float]]:
    """
    Get geolocation data from IP address using a third-party API.
    Returns (latitude, longitude) or None if lookup fails.
    """
    # Check cache first to reduce API calls
    if ip_address in location_cache:
        timestamp, location = location_cache[ip_address]
        if time.time() - timestamp < CACHE_EXPIRY:
            return location
    
    try:
        # Use a trusted geolocation API (replace with your preferred provider)
        headers = {"Authorization": f"Bearer {API_KEY}"}
        response = requests.get(
            f"https://ipgeolocation.example.com/api/v1/{ip_address}", 
            headers=headers,
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            latitude = float(data.get("latitude"))
            longitude = float(data.get("longitude"))
            
            # Store in cache
            location_cache[ip_address] = (time.time(), (latitude, longitude))
            return (latitude, longitude)
        else:
            logger.error(f"Failed to get location data. Status code: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"Error retrieving location data: {str(e)}")
        return None

def verify_location_access(user_role: str, user_location: Tuple[float, float]) -> Optional[str]:
    """
    Verify if a user's location grants them access based on their role.
    Returns the allowed region name if access is granted, None otherwise.
    """
    if user_role not in PERMISSION_LEVELS:
        logger.warning(f"Unknown role attempted access: {user_role}")
        return None
    
    allowed_regions = PERMISSION_LEVELS[user_role]
    user_lat, user_lon = user_location
    
    for region_name in allowed_regions:
        if region_name in ALLOWED_REGIONS:
            region_lat, region_lon, radius_km = ALLOWED_REGIONS[region_name]
            distance = calculate_distance(user_lat, user_lon, region_lat, region_lon)
            
            if distance <= radius_km:
                return region_name
    
    return None

def enforce_rate_limit(ip_address: str) -> bool:
    """
    Enforce rate limiting based on IP address.
    Returns True if request is allowed, False if rate limit exceeded.
    """
    current_time = time.time()
    
    if ip_address in rate_limit_store:
        count, first_request_time = rate_limit_store[ip_address]
        
        # Reset if outside time window
        if current_time - first_request_time > RATE_LIMIT["window_seconds"]:
            rate_limit_store[ip_address] = (1, current_time)
            return True
        
        # Increment and check
        count += 1
        rate_limit_store[ip_address] = (count, first_request_time)
        
        if count > RATE_LIMIT["max_requests"]:
            logger.warning(f"Rate limit exceeded for IP: {ip_address}")
            return False
    else:
        # First request from this IP
        rate_limit_store[ip_address] = (1, current_time)
    
    return True

def requires_location_access(roles=None):
    """
    Decorator for routes that require location-based access control.
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get client IP address
            ip_address = request.remote_addr
            
            # Apply rate limiting
            if not enforce_rate_limit(ip_address):
                return jsonify({
                    "error": "Rate limit exceeded, please try again later"
                }), 429
            
            # Check if IP is in allowed ranges
            if not is_ip_allowed(ip_address):
                logger.warning(f"Access attempt from unauthorized IP: {ip_address}")
                return jsonify({
                    "error": "Access denied: Your IP address is not authorized"
                }), 403
            
            # Verify authentication token
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({
                    "error": "Missing or invalid authorization token"
                }), 401
            
            token = auth_header.split(" ")[1]
            
            try:
                # Decrypt and verify token
                token_data = json.loads(decrypt_data(token))
                user_id = token_data.get("user_id")
                user_role = token_data.get("role")
                signature = token_data.get("signature")
                
                # Verify data integrity with HMAC
                data_to_verify = {
                    "user_id": user_id,
                    "role": user_role
                }
                
                if not verify_hmac(data_to_verify, signature, SECRET_KEY):
                    logger.warning(f"Failed HMAC verification for user: {user_id}")
                    return jsonify({
                        "error": "Invalid or tampered authentication token"
                    }), 401
                
                # Role-based access check
                if roles and user_role not in roles:
                    logger.warning(f"Unauthorized role access attempt: {user_role}")
                    return jsonify({
                        "error": "Your role does not have permission for this resource"
                    }), 403
                
                # Get user location from IP
                user_location = get_location_from_ip(ip_address)
                if not user_location:
                    logger.warning(f"Could not determine location for IP: {ip_address}")
                    return jsonify({
                        "error": "Could not verify your location"
                    }), 403
                
                # Check if location is allowed for this user
                allowed_region = verify_location_access(user_role, user_location)
                if not allowed_region:
                    lat, lon = user_location
                    logger.warning(f"Location access denied for user {user_id} at coordinates ({lat}, {lon})")
                    return jsonify({
                        "error": "Access denied based on your current location"
                    }), 403
                
                # Store user info for the route handler
                g.user = {
                    "id": user_id,
                    "role": user_role,
                    "location": user_location,
                    "region": allowed_region
                }
                
                return f(*args, **kwargs)
            
            except Exception as e:
                logger.error(f"Authentication error: {str(e)}")
                return jsonify({
                    "error": "Authentication failed"
                }), 401
        
        return wrapped
    return decorator

# Example of creating an authentication token (for demonstration purposes)
@app.route('/auth/token', methods=['POST'])
def generate_auth_token():
    """
    Generate an authentication token for a user.
    This endpoint would normally validate credentials first.
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.get_json()
    user_id = data.get("user_id")
    user_role = data.get("role")
    
    if not user_id or not user_role:
        return jsonify({"error": "Missing required fields"}), 400
    
    if user_role not in PERMISSION_LEVELS:
        return jsonify({"error": "Invalid role"}), 400
    
    # Data to include in token
    token_data = {
        "user_id": user_id,
        "role": user_role
    }
    
    # Generate signature for data integrity
    signature = generate_hmac(token_data, SECRET_KEY)
    
    # Include signature in the token
    token_data["signature"] = signature
    
    # Encrypt the token
    encrypted_token = encrypt_data(json.dumps(token_data))
    
    return jsonify({
        "token": encrypted_token,
        "expires_in": 3600  # Token valid for 1 hour
    })

# Protected resource example 
@app.route('/api/secure-resource', methods=['GET'])
@requires_location_access(roles=["admin", "manager"])
def access_secure_resource():
    """Example of a protected resource requiring location-based access."""
    user = g.user
    
    return jsonify({
        "message": "Access granted",
        "user_id": user["id"],
        "role": user["role"],
        "region": user["region"],
        "data": "This is sensitive data that requires location verification"
    })

# System health check endpoint (not protected)
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify system is running."""
    return jsonify({
        "status": "operational",
        "timestamp": time.time()
    })

if __name__ == "__main__":
    # In production, use a proper WSGI server and HTTPS
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
