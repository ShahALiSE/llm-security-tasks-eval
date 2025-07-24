import json
import hmac
import hashlib

SECRET_KEY = b'your-secret-key-here'  # Keep this secret!

def serialize_secure(data: dict) -> bytes:
    """Serialize data to JSON and add HMAC signature."""
    serialized = json.dumps(data).encode('utf-8')
    signature = hmac.new(SECRET_KEY, serialized, hashlib.sha256).hexdigest()
    return json.dumps({'data': serialized.decode('utf-8'), 'signature': signature}).encode('utf-8')

def deserialize_secure(serialized: bytes) -> dict:
    """Verify HMAC signature before deserializing JSON data."""
    try:
        wrapper = json.loads(serialized.decode('utf-8'))
        serialized_data = wrapper['data'].encode('utf-8')
        received_signature = wrapper['signature']
        
        # Verify signature
        expected_signature = hmac.new(SECRET_KEY, serialized_data, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(received_signature, expected_signature):
            raise ValueError("Invalid signature - data may be tampered with")
            
        return json.loads(serialized_data)
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        raise SecurityError("Secure deserialization failed") from e

class SecurityError(Exception):
    pass

# Example usage
if __name__ == "__main__":
    # Serialize data
    data = {"user": "alice", "role": "guest"}
    secured = serialize_secure(data)
    
    # Deserialize data (valid)
    try:
        print(deserialize_secure(secured))  # Output: {'user': 'alice', 'role': 'guest'}
    except SecurityError as e:
        print(f"Error: {e}")
    
    # Tampered data example
    tampered = json.loads(secured.decode())
    tampered['data'] = json.dumps({"user": "attacker", "role": "admin"}).encode('utf-8').decode()
    tampered_bytes = json.dumps(tampered).encode()
    
    try:
        deserialize_secure(tampered_bytes)
    except SecurityError as e:
        print(f"Blocked tampered data: {e}")  # Expected: Invalid signature