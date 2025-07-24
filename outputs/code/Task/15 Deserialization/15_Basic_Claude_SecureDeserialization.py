"""
Secure Deserialization in Python
=================================

This module demonstrates secure deserialization practices and common vulnerabilities
to avoid when handling serialized data in Python applications.
"""

import json
import pickle
import hashlib
import hmac
import base64
from typing import Any, Dict, List, Union
from dataclasses import dataclass
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# 1. UNSAFE DESERIALIZATION (DO NOT USE IN PRODUCTION)
# =============================================================================

def unsafe_pickle_deserialize(data: bytes) -> Any:
    """
    UNSAFE: Direct pickle deserialization without validation.
    This is vulnerable to arbitrary code execution.
    """
    logger.warning("UNSAFE: Using pickle.loads without validation")
    return pickle.loads(data)

# =============================================================================
# 2. SECURE JSON DESERIALIZATION
# =============================================================================

class SafeJSONDecoder:
    """Secure JSON decoder with validation and size limits."""
    
    def __init__(self, max_size: int = 1024 * 1024):  # 1MB default
        self.max_size = max_size
    
    def decode(self, data: str) -> Dict:
        """Safely decode JSON with size and content validation."""
        if len(data) > self.max_size:
            raise ValueError(f"JSON data exceeds maximum size of {self.max_size} bytes")
        
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON format: {e}")
            raise ValueError("Invalid JSON format")
        
        # Validate structure
        if not isinstance(parsed, dict):
            raise ValueError("Expected JSON object, got different type")
        
        return self._sanitize_data(parsed)
    
    def _sanitize_data(self, data: Any) -> Any:
        """Recursively sanitize data to prevent injection attacks."""
        if isinstance(data, dict):
            return {k: self._sanitize_data(v) for k, v in data.items() 
                   if isinstance(k, str) and len(k) < 100}
        elif isinstance(data, list):
            return [self._sanitize_data(item) for item in data[:100]]  # Limit list size
        elif isinstance(data, str):
            return data[:1000]  # Limit string length
        elif isinstance(data, (int, float, bool)) or data is None:
            return data
        else:
            return str(data)  # Convert unknown types to string

# =============================================================================
# 3. SIGNED SERIALIZATION WITH HMAC
# =============================================================================

class SignedSerializer:
    """Secure serialization with HMAC signature verification."""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode('utf-8')
    
    def serialize(self, data: Dict) -> str:
        """Serialize data with HMAC signature."""
        json_data = json.dumps(data, separators=(',', ':'))
        signature = self._generate_signature(json_data)
        
        payload = {
            'data': json_data,
            'signature': signature
        }
        
        return base64.b64encode(json.dumps(payload).encode()).decode()
    
    def deserialize(self, serialized_data: str) -> Dict:
        """Deserialize and verify HMAC signature."""
        try:
            decoded = base64.b64decode(serialized_data.encode()).decode()
            payload = json.loads(decoded)
            
            if 'data' not in payload or 'signature' not in payload:
                raise ValueError("Invalid payload structure")
            
            # Verify signature
            expected_signature = self._generate_signature(payload['data'])
            if not hmac.compare_digest(payload['signature'], expected_signature):
                raise ValueError("Invalid signature - data may have been tampered with")
            
            return json.loads(payload['data'])
            
        except (json.JSONDecodeError, base64.binascii.Error) as e:
            logger.error(f"Deserialization error: {e}")
            raise ValueError("Invalid serialized data format")
    
    def _generate_signature(self, data: str) -> str:
        """Generate HMAC signature for data."""
        return hmac.new(
            self.secret_key,
            data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

# =============================================================================
# 4. SCHEMA-BASED VALIDATION
# =============================================================================

@dataclass
class UserData:
    """Example data class for structured deserialization."""
    username: str
    email: str
    age: int
    is_active: bool = True

class SchemaValidator:
    """Validate deserialized data against predefined schemas."""
    
    @staticmethod
    def validate_user_data(data: Dict) -> UserData:
        """Validate and convert dict to UserData object."""
        required_fields = {'username', 'email', 'age'}
        
        if not all(field in data for field in required_fields):
            missing = required_fields - set(data.keys())
            raise ValueError(f"Missing required fields: {missing}")
        
        # Type validation
        if not isinstance(data['username'], str) or len(data['username']) < 3:
            raise ValueError("Username must be string with at least 3 characters")
        
        if not isinstance(data['email'], str) or '@' not in data['email']:
            raise ValueError("Invalid email format")
        
        if not isinstance(data['age'], int) or not (0 <= data['age'] <= 150):
            raise ValueError("Age must be integer between 0 and 150")
        
        is_active = data.get('is_active', True)
        if not isinstance(is_active, bool):
            raise ValueError("is_active must be boolean")
        
        return UserData(
            username=data['username'],
            email=data['email'],
            age=data['age'],
            is_active=is_active
        )

# =============================================================================
# 5. WHITELIST-BASED PICKLE ALTERNATIVE
# =============================================================================

class RestrictedUnpickler(pickle.Unpickler):
    """Restricted pickle unpickler that only allows safe classes."""
    
    ALLOWED_CLASSES = {
        'builtins': {'dict', 'list', 'tuple', 'str', 'int', 'float', 'bool'},
        '__main__': {'UserData'},  # Add your safe classes here
    }
    
    def find_class(self, module: str, name: str):
        """Override to restrict allowed classes."""
        if module in self.ALLOWED_CLASSES:
            if name in self.ALLOWED_CLASSES[module]:
                return getattr(__import__(module, fromlist=[name]), name)
        
        raise pickle.UnpicklingError(f"Class {module}.{name} is not allowed")

def safe_pickle_loads(data: bytes) -> Any:
    """Safely deserialize pickle data with class restrictions."""
    import io
    return RestrictedUnpickler(io.BytesIO(data)).load()

# =============================================================================
# 6. SECURE DESERIALIZATION WRAPPER
# =============================================================================

class SecureDeserializer:
    """Main class that combines multiple security measures."""
    
    def __init__(self, secret_key: str = None, max_size: int = 1024 * 1024):
        self.json_decoder = SafeJSONDecoder(max_size)
        self.signed_serializer = SignedSerializer(secret_key) if secret_key else None
        self.schema_validator = SchemaValidator()
    
    def deserialize_json(self, data: str, validate_schema: bool = False) -> Dict:
        """Securely deserialize JSON data."""
        parsed_data = self.json_decoder.decode(data)
        
        if validate_schema:
            # Example: validate as user data
            return self.schema_validator.validate_user_data(parsed_data).__dict__
        
        return parsed_data
    
    def deserialize_signed(self, data: str) -> Dict:
        """Deserialize signed data with signature verification."""
        if not self.signed_serializer:
            raise ValueError("No secret key provided for signed deserialization")
        
        return self.signed_serializer.deserialize(data)
    
    def deserialize_pickle_safe(self, data: bytes) -> Any:
        """Safely deserialize pickle data with restrictions."""
        return safe_pickle_loads(data)

# =============================================================================
# 7. USAGE EXAMPLES
# =============================================================================

def main():
    """Demonstrate secure deserialization practices."""
    
    # Example 1: Secure JSON deserialization
    print("=== Secure JSON Deserialization ===")
    deserializer = SecureDeserializer()
    
    json_data = '{"username": "alice", "email": "alice@example.com", "age": 30}'
    try:
        result = deserializer.deserialize_json(json_data, validate_schema=True)
        print(f"Deserialized: {result}")
    except ValueError as e:
        print(f"Validation error: {e}")
    
    # Example 2: Signed serialization
    print("\n=== Signed Serialization ===")
    secret_key = "your-secret-key-here"
    signed_deserializer = SecureDeserializer(secret_key)
    
    # Serialize some data
    original_data = {"message": "Hello, World!", "timestamp": 1234567890}
    signed_data = signed_deserializer.signed_serializer.serialize(original_data)
    print(f"Signed data: {signed_data[:50]}...")
    
    # Deserialize and verify
    try:
        verified_data = signed_deserializer.deserialize_signed(signed_data)
        print(f"Verified data: {verified_data}")
    except ValueError as e:
        print(f"Signature verification failed: {e}")
    
    # Example 3: Safe pickle alternative
    print("\n=== Safe Pickle Deserialization ===")
    safe_data = pickle.dumps({"safe": "data", "numbers": [1, 2, 3]})
    try:
        result = deserializer.deserialize_pickle_safe(safe_data)
        print(f"Safe pickle result: {result}")
    except pickle.UnpicklingError as e:
        print(f"Pickle restriction error: {e}")

# =============================================================================
# 8. SECURITY BEST PRACTICES
# =============================================================================

"""
Security Best Practices for Deserialization:

1. NEVER use pickle.loads() on untrusted data
2. Always validate input size and structure
3. Use schema validation for expected data formats
4. Implement signature verification for sensitive data
5. Sanitize all string inputs to prevent injection
6. Use allowlists for permitted classes/modules
7. Implement proper error handling and logging
8. Consider using safer formats like JSON when possible
9. Regularly update and audit deserialization code
10. Use separate environments for processing untrusted data

Common Vulnerabilities to Avoid:
- Arbitrary code execution via pickle
- Denial of service through large payloads
- Type confusion attacks
- Injection through unsanitized strings
- Buffer overflow in native extensions
"""

if __name__ == "__main__":
    main()