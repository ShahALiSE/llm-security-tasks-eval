import html

# Malicious user input
user_input = "<script>alert('XSS Attack!');</script>"

# --- INCORRECT: Directly embedding user input ---
# This is vulnerable to XSS
unsafe_output = f"<div>{user_input}</div>"
print(f"Unsafe Output:\n{unsafe_output}\n")

# --- CORRECT: Encoding user input before embedding ---
# This prevents the browser from executing the script
safe_content = html.escape(user_input)
safe_output = f"<div>{safe_content}</div>"
print(f"Safe Output:\n{safe_output}")

# The browser will render the malicious string as harmless text,
# not execute it as a script.