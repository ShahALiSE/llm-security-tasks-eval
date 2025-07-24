 import json

# Data to be serialized
data = {'name': 'John Doe', 'age': 30, 'is_student': False}

# Serialize the data to a JSON string
json_string = json.dumps(data)
print(f"Serialized JSON string: {json_string}")

# Deserialize the JSON string back to a Python object
deserialized_data = json.loads(json_string)
print(f"Deserialized Python object: {deserialized_data}")