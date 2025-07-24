import json
import hmac
import hashlib
import secrets
import base64
from typing import Any, Dict

# Generate a cryptographically secure secret key (32 bytes recommended for HMAC-SHA256)
SECRET_KEY = secrets.token_bytes(32)

def sign_data(data: bytes) -> bytes:
    """Generate HMAC signature for data using SHA-256."""
    return hmac.new(SECRET_KEY, data, digestmod=hashlib.sha256).digest()

def verify_signature(data: bytes, signature: bytes) -> bool:
    """Verify data integrity with constant-time HMAC comparison."""
    expected_sig = sign_data(data)
    return hmac.compare_digest(expected_sig, signature)

def serialize_securely(data: Any) -> str:
    """
    Serialize data to JSON and append base64-encoded HMAC signature.
    Format: <base64_json_data>.<base64_signature>
    """
    json_data = json.dumps(data).encode('utf-8')
    signature = sign_data(json_data)
    return f"{base64.b64encode(json_data).decode()}@{base64.b64encode(signature).decode()}"

def deserialize_securely(serialized_data: str) -> Any:
    """
    Deserialize data after verifying HMAC signature.
    Raises ValueError if verification fails.
    """
    try:
        json_b64, signature_b64 = serialized_data.split('@', 1)
        json_data = base64.b64decode(json_b64)
        signature = base64.b64decode(signature_b64)
    except (ValueError, binascii.Error) as e:
        raise ValueError("Malformed data") from e

    if not verify_signature(json_data, signature):
        raise ValueError("Invalid signature or tampered data")

    return json.loads(json_data)

# Example Usage
if __name__ == "__main__":
    # Serialize sensitive data
    payload = {"user": "alice", "admin": False}
    secured = serialize_securely(payload)
    print("Secured Data:", secured)

    # Deserialize and verify
    try:
        result = deserialize_securely(secured)
        print("Deserialized Data:", result)
    except ValueError as e:
        print("Deserialization Failed:", str(e))