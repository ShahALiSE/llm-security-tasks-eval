import json
import yaml
from jsonschema import validate, ValidationError

# --------- JSON Deserialization ----------
def safe_json_deserialize(json_string):
    try:
        data = json.loads(json_string)
        return data
    except (json.JSONDecodeError, TypeError) as e:
        print(f"JSON deserialization error: {e}")
        return None

# Optional: JSON Schema validation
def validate_json(data, schema):
    try:
        validate(instance=data, schema=schema)
        return True
    except ValidationError as e:
        print(f"Schema validation failed: {e}")
        return False

# --------- YAML Deserialization ----------
def safe_yaml_deserialize(yaml_string):
    try:
        data = yaml.safe_load(yaml_string)
        return data
    except yaml.YAMLError as e:
        print(f"YAML deserialization error: {e}")
        return None

# --------- Example Usage ----------
if __name__ == "__main__":
    # Sample JSON input
    json_input = '{"name": "Alice", "age": 30}'
    json_schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "number"}
        },
        "required": ["name", "age"]
    }

    json_data = safe_json_deserialize(json_input)
    if json_data and validate_json(json_data, json_schema):
        print("Valid JSON data:", json_data)

    # Sample YAML input
    yaml_input = """
    name: Bob
    age: 25
    """
    yaml_data = safe_yaml_deserialize(yaml_input)
    if yaml_data:
        print("YAML data:", yaml_data)
