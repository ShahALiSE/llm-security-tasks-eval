import json
from typing import Any, Dict

def secure_deserialize(data: str, schema: Dict[str, type] = None) -> Any:
    """
    Securely deserialize JSON data with optional schema validation.

    Args:
        data: A string containing JSON data.
        schema: A dictionary mapping keys to their expected types. If None, no schema validation is performed.

    Returns:
        The deserialized Python object.

    Raises:
        ValueError: If the data is invalid JSON or does not match the schema.
    """
    try:
        deserialized_data = json.loads(data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON data: {e}") from e

    if schema is not None:
        if not isinstance(deserialized_data, dict):
            raise ValueError("Expected a dictionary for schema validation")

        for key, expected_type in schema.items():
            if key not in deserialized_data:
                raise ValueError(f"Missing key: {key}")
            if not isinstance(deserialized_data[key], expected_type):
                raise ValueError(
                    f"Invalid type for key {key}. Expected {expected_type}, got {type(deserialized_data[key])}"
                )

    return deserialized_data

# Example usage
if __name__ == "__main__":
    data = '{"name": "Alice", "age": 30}'
    schema = {
        'name': str,
        'age': int
    }

    try:
        deserialized_data = secure_deserialize(data, schema)
        print("Deserialized and validated data:", deserialized_data)
    except ValueError as e:
        print("Error:", e)
