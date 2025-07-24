
import json
from itsdangerous import Signer, BadSignature, TimestampSigner
from time import sleep

# --- Configuration ---

# ⚠️ IMPORTANT: Keep this key secret and secure in a real application.
# It should be a long, random string, ideally loaded from an environment variable
# or a secrets management system.
SECRET_KEY = 'my-super-secret-and-long-random-string-for-security'


# --- Main Demonstration Logic ---

def demonstrate_secure_deserialization():
    """
    Runs a full demonstration of signing, verifying, and deserializing data.
    """
    print("--- 1. Starting Secure Serialization and Signing ---")
    
    # Original data to protect
    original_data = {
        'user_id': 'AB-12345',
        'session_id': 'a7d8f9b0-c1e2-4d56-8a9b-0123456789cf',
        'roles': ['user', 'reader'],
        'is_admin': False
    }
    print(f"Original Python object:\n{original_data}\n")


    # Use a Signer for basic integrity checks
    signer = Signer(SECRET_KEY, salt='data-integrity')

    # Serialize to JSON and sign
    json_payload = json.dumps(original_data).encode('utf-8')
    signed_payload = signer.sign(json_payload)

    print(f"Serialized and Signed Payload (to be transmitted or stored):\n{signed_payload.decode('utf-8')}\n")


    # --- 2. Simulating a Secure Deserialization Process ---
    print("--- 2. Receiving payload and performing Secure Deserialization ---")
    
    try:
        # Verify signature and get original bytes back
        unsigned_payload_bytes = signer.unsign(signed_payload)
        
        # Deserialize the verified JSON
        deserialized_data = json.loads(unsigned_payload_bytes)
        
        print("✅ SUCCESS: Signature is valid.")
        print(f"Deserialized Python object:\n{deserialized_data}\n")
        
    except BadSignature:
        print("❌ FAILURE: Signature verification failed. Data may be corrupt or tampered with.")
    except json.JSONDecodeError:
        print("❌ FAILURE: Payload is not valid JSON, even though signature was correct.")


    # --- 3. Simulating a Tampering Attempt ---
    print("--- 3. Simulating a Tampering Attempt ---")
    
    # An attacker intercepts the payload and tries to change 'is_admin' to True
    # They don't have the SECRET_KEY, so they cannot generate a valid signature.
    tampered_payload_string = signed_payload.decode('utf-8')
    # This naive modification will invalidate the signature
    tampered_payload_string = tampered_payload_string.replace('"is_admin": false', '"is_admin": true')
    tampered_payload_bytes = tampered_payload_string.encode('utf-8')
    
    print(f"Received tampered payload:\n{tampered_payload_bytes.decode('utf-8')}\n")
    
    try:
        # This will fail and raise BadSignature
        signer.unsign(tampered_payload_bytes)
    except BadSignature:
        print("✅ SUCCESS: Tampering detected! BadSignature exception was correctly raised.\n")


def demonstrate_timed_signature():
    """
    Demonstrates using a timestamp to create expiring data.
    """
    print("--- 4. Bonus: Demonstrating Timed (Expiring) Signatures ---")
    
    # Use a TimestampSigner to add an expiration check
    ts_signer = TimestampSigner(SECRET_KEY, salt='expiring-token')
    
    reset_link_data = {'user_id': 'AB-12345', 'action': 'password-reset'}
    json_payload = json.dumps(reset_link_data).encode('utf-8')
    
    # Sign with a timestamp
    signed_payload_with_ts = ts_signer.sign(json_payload)
    print(f"Generated expiring token:\n{signed_payload_with_ts.decode('utf-8')}\n")
    
    # Verify immediately (should succeed)
    try:
        # max_age is in seconds. Let's check within a 60-second window.
        unsigned_payload = ts_signer.unsign(signed_payload_with_ts, max_age=60)
        deserialized_data = json.loads(unsigned_payload)
        print(f"✅ SUCCESS: Token is valid and has not expired.")
        print(f"Deserialized data: {deserialized_data}\n")
    except Exception as e:
        print(f"❌ FAILURE: Verification failed unexpectedly: {e}\n")
        
    # Verify after a delay (should fail)
    print("Waiting 3 seconds to simulate token expiration...")
    sleep(3)
    
    try:
        # Now set max_age to 2 seconds, which is less than our 3-second sleep
        ts_signer.unsign(signed_payload_with_ts, max_age=2)
    except BadSignature as e:
        # The specific error for expired tokens is itsdangerous.SignatureExpired
        print(f"✅ SUCCESS: Expired token was correctly rejected. Error: {e}")


if __name__ == '__main__':
    demonstrate_secure_deserialization()
    demonstrate_timed_signature()
