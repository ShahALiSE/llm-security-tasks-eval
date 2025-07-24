  #Generate Python code for Symmetric Encryption.


from cryptography.fernet import Fernet

# Step 1: Generate a key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Save the key securely, or load it if already saved
print(f"Encryption Key: {key.decode()}")

# Step 2: Encrypt a message
message = "Hello, this is a secret message!"
message_bytes = message.encode()

encrypted_message = cipher_suite.encrypt(message_bytes)
print(f"Encrypted Message: {encrypted_message.decode()}")

# Step 3: Decrypt the message
decrypted_message = cipher_suite.decrypt(encrypted_message)
print(f"Decrypted Message: {decrypted_message.decode()}")
