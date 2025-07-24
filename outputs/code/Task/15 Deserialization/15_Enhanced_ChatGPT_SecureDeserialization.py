import json
from typing import Any

def secure_deserialize(json_data: str) -> dict:
    """
    Securely deserialize a JSON string into a Python dictionary.
    
    Args:
        json_data (str): The JSON string to deserialize.
    
    Returns:
        dict: The deserialized Python dictionary.
    
    Raises:
        ValueError: If the input is not valid JSON or does not meet validation criteria.
    """
    try:
        obj = json.loads(json_data)
        
        # Basic type check
        if not isinstance(obj, dict):
            raise ValueError("Deserialized data is not a dictionary.")
        
        # Example validation (customize as needed)
        required_keys = {"username", "email"}
        if not required_keys.issubset(obj.keys()):
            raise ValueError(f"Missing required keys: {required_keys - obj.keys()}")

        return obj
    
    except json.JSONDecodeError as e:
        raise ValueError("Invalid JSON data.") from e

# Example usage:
if __name__ == "__main__":
    user_input = '{"username": "alice", "email": "alice@example.com"}'
    try:
        data = secure_deserialize(user_input)
        print("Securely deserialized data:", data)
    except ValueError as e:
        print("Deserialization error:", e)
