#!/usr/bin/env python3
"""
Secure Deserialization Examples for Python
Demonstrates safe practices for deserializing data from untrusted sources.
"""

import json
import pickle
import hashlib
import hmac
import logging
from typing import Any, Dict, List, Union, Optional
from dataclasses import dataclass
from enum import Enum
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SerializationError(Exception):
    """Custom exception for serialization/deserialization errors."""
    pass


class AllowedTypes(Enum):
    """Enumeration of allowed types for safe deserialization."""
    STRING = str
    INTEGER = int
    FLOAT = float
    BOOLEAN = bool
    LIST = list
    DICT = dict


@dataclass
class SecureData:
    """Example data class for type safety."""
    name: str
    age: int
    email: str
    active: bool = True

    def __post_init__(self):
        """Validate data after initialization."""
        if not isinstance(self.name, str) or len(self.name.strip()) == 0:
            raise ValueError("Name must be a non-empty string")
        if not isinstance(self.age, int) or self.age < 0 or self.age > 150:
            raise ValueError("Age must be an integer between 0 and 150")
        if not isinstance(self.email, str) or '@' not in self.email:
            raise ValueError("Email must be a valid string containing @")


class SecureDeserializer:
    """Secure deserialization utility class."""
    
    def __init__(self, secret_key: str):
        """Initialize with a secret key for HMAC verification."""
        self.secret_key = secret_key.encode('utf-8')
        self.max_payload_size = 1024 * 1024  # 1MB limit
    
    def _generate_hmac(self, data: bytes) -> str:
        """Generate HMAC signature for data integrity."""
        return hmac.new(self.secret_key, data, hashlib.sha256).hexdigest()
    
    def _verify_hmac(self, data: bytes, signature: str) -> bool:
        """Verify HMAC signature."""
        expected_signature = self._generate_hmac(data)
        return hmac.compare_digest(expected_signature, signature)
    
    def secure_json_serialize(self, obj: Any) -> str:
        """Securely serialize object to JSON with HMAC."""
        try:
            # Convert to JSON
            json_data = json.dumps(obj, separators=(',', ':'), ensure_ascii=True)
            json_bytes = json_data.encode('utf-8')
            
            # Generate signature
            signature = self._generate_hmac(json_bytes)
            
            # Combine data and signature
            payload = {
                'data': base64.b64encode(json_bytes).decode('ascii'),
                'signature': signature
            }
            
            return json.dumps(payload)
            
        except (TypeError, ValueError) as e:
            raise SerializationError(f"JSON serialization failed: {e}")
    
    def secure_json_deserialize(self, serialized_data: str, expected_type: type = None) -> Any:
        """Securely deserialize JSON with HMAC verification."""
        try:
            # Check payload size
            if len(serialized_data) > self.max_payload_size:
                raise SerializationError("Payload exceeds maximum size limit")
            
            # Parse outer JSON
            payload = json.loads(serialized_data)
            
            if not isinstance(payload, dict) or 'data' not in payload or 'signature' not in payload:
                raise SerializationError("Invalid payload format")
            
            # Decode data
            try:
                json_bytes = base64.b64decode(payload['data'].encode('ascii'))
            except Exception:
                raise SerializationError("Invalid base64 encoding")
            
            # Verify signature
            if not self._verify_hmac(json_bytes, payload['signature']):
                raise SerializationError("HMAC verification failed - data may be tampered")
            
            # Deserialize JSON
            obj = json.loads(json_bytes.decode('utf-8'))
            
            # Type validation if expected type is provided
            if expected_type and not isinstance(obj, expected_type):
                raise SerializationError(f"Expected type {expected_type}, got {type(obj)}")
            
            return obj
            
        except json.JSONDecodeError as e:
            raise SerializationError(f"JSON deserialization failed: {e}")
        except Exception as e:
            raise SerializationError(f"Deserialization error: {e}")


class SafePickleDeserializer:
    """
    Demonstration of safe pickle alternatives.
    WARNING: This is for educational purposes. Avoid pickle with untrusted data.
    """
    
    SAFE_BUILTINS = {
        'str', 'int', 'float', 'bool', 'list', 'dict', 'tuple', 'set',
        'frozenset', 'bytes', 'bytearray'
    }
    
    @classmethod
    def restricted_loads(cls, data: bytes) -> Any:
        """
        Restricted pickle loads - STILL NOT RECOMMENDED for untrusted data.
        This is for demonstration only.
        """
        # This is a simplified example - real implementations need more restrictions
        logger.warning("Using pickle with restrictions - still not safe for untrusted data!")
        
        # In practice, you should never use pickle for untrusted data
        # This is just to show the concept
        try:
            return pickle.loads(data)
        except Exception as e:
            raise SerializationError(f"Pickle deserialization failed: {e}")


def validate_json_structure(data: Any, schema: Dict) -> bool:
    """
    Simple JSON schema validation.
    For production use, consider using jsonschema library.
    """
    if 'type' in schema:
        expected_type = schema['type']
        if expected_type == 'object' and not isinstance(data, dict):
            return False
        elif expected_type == 'array' and not isinstance(data, list):
            return False
        elif expected_type == 'string' and not isinstance(data, str):
            return False
        elif expected_type == 'number' and not isinstance(data, (int, float)):
            return False
        elif expected_type == 'boolean' and not isinstance(data, bool):
            return False
    
    if 'properties' in schema and isinstance(data, dict):
        for key, value_schema in schema['properties'].items():
            if key in data:
                if not validate_json_structure(data[key], value_schema):
                    return False
            elif schema.get('required', []) and key in schema['required']:
                return False
    
    if 'maxLength' in schema and isinstance(data, str):
        if len(data) > schema['maxLength']:
            return False
    
    return True


def sanitize_input(data: Any, allowed_types: List[type] = None) -> Any:
    """Sanitize input data by checking types and values."""
    if allowed_types is None:
        allowed_types = [str, int, float, bool, list, dict]
    
    if not any(isinstance(data, t) for t in allowed_types):
        raise ValueError(f"Type {type(data)} not in allowed types: {allowed_types}")
    
    if isinstance(data, str):
        # Basic string sanitization
        if len(data) > 10000:  # Prevent extremely long strings
            raise ValueError("String too long")
        # Remove null bytes and control characters except newlines/tabs
        data = ''.join(char for char in data if ord(char) >= 32 or char in '\n\t')
    
    elif isinstance(data, (list, tuple)):
        if len(data) > 1000:  # Prevent extremely large lists
            raise ValueError("List too long")
        data = [sanitize_input(item, allowed_types) for item in data]
    
    elif isinstance(data, dict):
        if len(data) > 1000:  # Prevent extremely large dicts
            raise ValueError("Dictionary too large")
        sanitized = {}
        for key, value in data.items():
            if not isinstance(key, str):
                raise ValueError("Dictionary keys must be strings")
            sanitized[sanitize_input(key, [str])] = sanitize_input(value, allowed_types)
        data = sanitized
    
    return data


# Example usage and demonstrations
def main():
    """Demonstrate secure deserialization practices."""
    
    # Initialize secure deserializer
    deserializer = SecureDeserializer("your-secret-key-here-change-this")
    
    # Example 1: Secure JSON serialization/deserialization
    print("=== Secure JSON Example ===")
    
    original_data = {
        "name": "John Doe",
        "age": 30,
        "email": "john@example.com",
        "preferences": ["security", "python", "encryption"]
    }
    
    try:
        # Serialize with HMAC
        serialized = deserializer.secure_json_serialize(original_data)
        print(f"Serialized data length: {len(serialized)} bytes")
        
        # Deserialize with verification
        deserialized = deserializer.secure_json_deserialize(serialized, expected_type=dict)
        print(f"Deserialized successfully: {deserialized}")
        print(f"Data integrity verified: {original_data == deserialized}")
        
    except SerializationError as e:
        logger.error(f"Serialization error: {e}")
    
    # Example 2: Input sanitization
    print("\n=== Input Sanitization Example ===")
    
    unsafe_data = {
        "name": "Alice\x00\x01\x02",  # Contains null bytes
        "scores": [95, 87, 92],
        "active": True
    }
    
    try:
        sanitized = sanitize_input(unsafe_data)
        print(f"Sanitized data: {sanitized}")
    except ValueError as e:
        logger.error(f"Sanitization error: {e}")
    
    # Example 3: Structured data validation
    print("\n=== Structured Data Validation Example ===")
    
    try:
        user_data = SecureData(
            name="Bob Smith",
            age=25,
            email="bob@company.com"
        )
        print(f"Valid user data: {user_data}")
        
        # This will raise an exception
        # invalid_user = SecureData(name="", age=-5, email="invalid")
        
    except ValueError as e:
        logger.error(f"Validation error: {e}")
    
    # Example 4: Schema validation
    print("\n=== Schema Validation Example ===")
    
    schema = {
        "type": "object",
        "properties": {
            "username": {"type": "string", "maxLength": 50},
            "age": {"type": "number"},
            "active": {"type": "boolean"}
        },
        "required": ["username", "age"]
    }
    
    test_data = {
        "username": "testuser",
        "age": 28,
        "active": True
    }
    
    if validate_json_structure(test_data, schema):
        print("Data matches schema")
    else:
        print("Data does not match schema")
    
    print("\n=== Security Best Practices Summary ===")
    print("1. Never use pickle.loads() with untrusted data")
    print("2. Always validate and sanitize input data")
    print("3. Use HMAC for data integrity verification")
    print("4. Implement size limits to prevent DoS attacks")
    print("5. Use type hints and validation for structured data")
    print("6. Prefer JSON over binary serialization formats")
    print("7. Implement proper error handling and logging")


if __name__ == "__main__":
    main()