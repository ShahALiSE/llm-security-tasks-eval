# -*- coding: utf-8 -*-
"""
A single-file demonstration of secure password hashing in Python.

This file covers two recommended libraries: `bcrypt` and `passlib`.
It is crucial to use libraries designed for password hashing, as they
incorporate security best practices like salting and adjustable work factors.

To run this code, you will need to install the necessary libraries.
You can install them using pip:
pip install bcrypt passlib[bcrypt]
"""

import bcrypt
from passlib.context import CryptContext

# --- Part 1: Using the `bcrypt` library ---
# `bcrypt` is a widely used and respected library for password hashing.
# It directly implements the bcrypt algorithm.

print("--- Demonstrating with `bcrypt` library ---")

def bcrypt_example():
    """
    Shows how to hash and verify a password using the `bcrypt` library.
    """
    print("\n[bcrypt] Hashing a new password...")
    # The password must be in bytes.
    password_to_hash = b"a_very_secret_password_123"

    # 1. Hashing the password
    # bcrypt.gensalt() creates a random salt. The work factor can be adjusted
    # (default is 12). A higher number is more secure but slower.
    salt = bcrypt.gensalt(rounds=12)
    hashed_password = bcrypt.hashpw(password_to_hash, salt)

    print(f"[bcrypt] Original Password: {password_to_hash.decode()}")
    print(f"[bcrypt] Hashed Password (safe to store): {hashed_password.decode()}")

    # The generated hash contains the algorithm, work factor, salt, and hash digest.
    # e.g., $2b$12$E4/c.0.C2.Fk3iXk3mJp6e8p.m9.Z7b3pS.gQ2/qQ3kR1rT1nO1W
    #       \__/ \_/ \____________________/ \_____________________________/
    #       Alg Cost        Salt (22 chars)        Hash (31 chars)


    # 2. Verifying the password
    print("\n[bcrypt] Verifying passwords...")
    user_provided_password_correct = b"a_very_secret_password_123"
    user_provided_password_incorrect = b"wrong_password_!@#"

    # Use bcrypt.checkpw() to compare a plaintext password with the stored hash.
    # It automatically extracts the salt from the hashed_password.
    if bcrypt.checkpw(user_provided_password_correct, hashed_password):
        print("[bcrypt] Verification PASSED for the correct password.")
    else:
        print("[bcrypt] Verification FAILED for the correct password.")

    if not bcrypt.checkpw(user_provided_password_incorrect, hashed_password):
        print("[bcrypt] Verification CORRECTLY FAILED for the incorrect password.")
    else:
        print("[bcrypt] Verification INCORRECTLY PASSED for the incorrect password.")


# --- Part 2: Using the `passlib` library ---
# `passlib` is a higher-level library that provides a unified interface for
# many different hashing algorithms. It simplifies management and is highly recommended.

print("\n\n--- Demonstrating with `passlib` library ---")

def passlib_example():
    """
    Shows how to hash and verify a password using the `passlib` library.
    """
    # 1. Configure the CryptContext
    # This is the recommended approach. You define your policies once.
    # - `schemes`: A list of allowed hashing algorithms. The first is the default.
    # - `deprecated="auto"`: Automatically marks older hashes for re-hashing upon
    #   successful verification, allowing for seamless security upgrades.
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    password_to_hash = "another_Super_s3cret_Pa$$word"
    print(f"\n[passlib] Original Password: {password_to_hash}")

    # 2. Hashing the password
    # `passlib` handles salting and work factors automatically based on the context.
    hashed_password = pwd_context.hash(password_to_hash)
    print(f"[passlib] Hashed Password (safe to store): {hashed_password}")


    # 3. Verifying the password
    print("\n[passlib] Verifying passwords...")
    user_provided_password_correct = "another_Super_s3cret_Pa$$word"
    user_provided_password_incorrect = "guess-again"

    # Use the verify method from the context object.
    if pwd_context.verify(user_provided_password_correct, hashed_password):
        print("[passlib] Verification PASSED for the correct password.")
    else:
        print("[passlib] Verification FAILED for the correct password.")

    if not pwd_context.verify(user_provided_password_incorrect, hashed_password):
        print("[passlib] Verification CORRECTLY FAILED for the incorrect password.")
    else:
        print("[passlib] Verification INCORRECTLY PASSED for the incorrect password.")

    # 4. (Optional) Identifying and updating hashes
    # If you verify against a hash using a deprecated scheme, verify_and_update can
    # automatically re-hash it with your new default scheme.
    # This is useful for upgrading your users' password hashes over time.
    # Note: `passlib` needs to know about the old scheme to do this.
    # old_md5_hash = "some_old_md5_hash_from_a_legacy_system" # Example
    # needs_update = pwd_context.needs_update(old_md5_hash)
    # if needs_update:
    #     print("\n[passlib] This hash uses a deprecated scheme and should be updated.")


if __name__ == "__main__":
    # Run the examples
    bcrypt_example()
    passlib_example()

    print("\n\n--- Summary ---")
    print("Both `bcrypt` and `passlib` are excellent choices.")
    print("`passlib` is often preferred for new applications due to its high-level API,")
    print("which simplifies hash management, verification, and future algorithm upgrades.")