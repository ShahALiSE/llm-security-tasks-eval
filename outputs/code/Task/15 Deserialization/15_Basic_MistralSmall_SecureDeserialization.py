import json
from datetime import datetime

# Registry of allowed classes
class_registry = {
    'datetime': datetime,
    # Add other allowed classes here
}

class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return {"__type__": "datetime", "isoformat": obj.isoformat()}
        if hasattr(obj, '__dict__'):
            return {
                "__type__": obj.__class__.__name__,
                "__data__": obj.__dict__,
            }
        return super().default(obj)

def custom_decoder(dct):
    if '__type__' in dct:
        class_name = dct['__type__']
        if class_name in class_registry:
            cls = class_registry[class_name]
            if class_name == 'datetime':
                return datetime.fromisoformat(dct['isoformat'])
            else:
                # For custom classes, we assume they can be initialized with **kwargs
                obj = cls.__new__(cls)  # Create a new instance without calling __init__
                obj.__dict__ = dct['__data__']
                return obj
        else:
            raise ValueError(f"Class {class_name} not allowed")
    return dct

def serialize(data):
    """Serialize data to a JSON string and encode to bytes."""
    return json.dumps(data, cls=CustomEncoder).encode('utf-8')

def deserialize(serialized_data):
    """Deserialize JSON data from bytes to a Python object."""
    return json.loads(serialized_data.decode('utf-8'), object_hook=custom_decoder)

# Example usage with a custom class
class Person:
    def __init__(self, name, age):
        self.name = name
        self.age = age

    def __repr__(self):
        return f"Person(name={self.name}, age={self.age})"

# Register the Person class
class_registry['Person'] = Person

# Example usage
data = {
    "person": Person("Alice", 30),
    "event": {"time": datetime.now()}
}
serialized_data = serialize(data)
deserialized_data = deserialize(serialized_data)
print(deserialized_data)
