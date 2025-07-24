# single_file_xss_prevention.py

import html
import json
from urllib.parse import quote
import bleach
from jinja2 import Environment

def print_section_header(title):
    """Helper function to print a formatted section header."""
    print("\n" + "="*60)
    print(f"// {title.upper()}")
    print("="*60)


# --- 1. ENCODING FOR HTML BODY CONTENT ---
print_section_header("1. Encoding for HTML Body Content")

user_input = "<script>alert('XSS in body!');</script>"

print(f"Original user input: {user_input}")

# SECURE: Use html.escape() to make the input safe for HTML body.
secure_body_output = html.escape(user_input)
print(f"\n[SECURE]   Encoded output: {secure_body_output}")
print(f"[SECURE]   Resulting HTML: <div>{secure_body_output}</div>")

# INSECURE: Directly embedding user input leads to XSS.
# insecure_body_output = f"<div>{user_input}</div>"
# print(f"\n[INSECURE] Resulting HTML: {insecure_body_output}")
print("\n[INSECURE] Example commented out to prevent accidental execution.")
print("[INSECURE] Direct injection `<div>{user_input}</div>` would be vulnerable.")


# --- 2. ENCODING FOR HTML ATTRIBUTE VALUES ---
print_section_header("2. Encoding for HTML Attribute Values")

attribute_input = '"><script>alert("XSS in attribute!")</script>'
print(f"Original user input for attribute: {attribute_input}")

# SECURE: Use html.escape() and always quote attributes.
secure_attribute_output = html.escape(attribute_input)
print(f"\n[SECURE]   Encoded output: {secure_attribute_output}")
print(f"[SECURE]   Resulting HTML: <input type=\"text\" value=\"{secure_attribute_output}\">")

# INSECURE: Unencoded input can break out of the attribute.
# insecure_attribute_output = f"<input type=\"text\" value=\"{attribute_input}\">"
# print(f"\n[INSECURE] Resulting HTML: {insecure_attribute_output}")
print("\n[INSECURE] Example commented out to prevent accidental execution.")
print("[INSECURE] Direct injection `<input value=\"{attribute_input}\">` would be vulnerable.")


# --- 3. ENCODING FOR JAVASCRIPT CONTEXTS ---
print_section_header("3. Encoding for JavaScript Contexts")

js_data = {"username": "John 'Johnny' Doe", "bio": "Bio with a </script><script>alert('XSS in JS!')</script> payload"}
print(f"Original Python dictionary: {js_data}")

# SECURE: Use json.dumps() to safely serialize Python objects for JavaScript.
secure_js_output = json.dumps(js_data)
print(f"\n[SECURE]   Encoded for JS: {secure_js_output}")
secure_html_script = f"""
<script>
    // Data is safely loaded into the JavaScript variable
    var userData = {secure_js_output};
    console.log('Username from JS:', userData.username);
    document.getElementById('some_element').innerText = userData.bio;
</script>
"""
print(f"[SECURE]   Resulting HTML block (simplified view):\n{secure_html_script}")


# --- 4. URL ENCODING FOR HREF/SRC ATTRIBUTES ---
print_section_header("4. URL Encoding for href/src Attributes")

# Example 1: Malicious Path
malicious_path = "../../../etc/passwd"
print(f"Original path input: {malicious_path}")

# SECURE: Use urllib.parse.quote() to encode URL segments.
secure_url_segment = quote(malicious_path)
print(f"\n[SECURE]   Encoded path: {secure_url_segment}")
print(f"[SECURE]   Resulting HTML: <a href=\"/user/profile/{secure_url_segment}\">View Profile</a>")

# Example 2: Malicious URL Scheme
malicious_url = "javascript:alert('XSS in URL!')"
print(f"\nOriginal URL input: {malicious_url}")

def is_safe_url_scheme(url):
    """Validates that a URL uses a safe protocol (http, https, or is relative)."""
    return url.startswith(('http://', 'https://', '/'))

# SECURE: Validate the URL scheme before using it.
if is_safe_url_scheme(malicious_url):
    # This code will not run for the malicious URL
    safe_html_link = f'<a href="{html.escape(malicious_url)}">User Link</a>'
else:
    print("[SECURE]   Blocked unsafe URL scheme 'javascript:'.")

# INSECURE: Directly using a URL without validation.
# insecure_link = f'<a href="{malicious_url}">Click me!</a>'
# print(f"\n[INSECURE] Resulting HTML: {insecure_link}")
print("\n[INSECURE] Example commented out to prevent accidental execution.")
print("[INSECURE] Direct injection `<a href=\"{malicious_url}\">` would be vulnerable.")


# --- 5. SANITIZING USER-SUPPLIED HTML ---
print_section_header("5. Sanitizing User-Supplied HTML with Bleach")

html_input = 'An <script>evil()</script> example with <a href="javascript:alert(1)" onclick="evil()">a link</a>, <b>bold text</b>, and <p style="color:red">red text</p>.'
print(f"Original HTML input: {html_input}")

# SECURE: Use bleach.clean() with a whitelist of allowed tags and attributes.
allowed_tags = ['b', 'i', 'u', 'a', 'p']
allowed_attributes = {'a': ['href', 'title'], 'p': ['style']} # Note: allowing 'style' can be risky

# Sanitize the input
sanitized_output = bleach.clean(
    html_input,
    tags=allowed_tags,
    attributes=allowed_attributes,
    strip=True # Removes disallowed tags instead of escaping them
)
print(f"\n[SECURE]   Sanitized HTML: {sanitized_output}")
print("[SECURE]   Note: Malicious script and onclick are removed, href is stripped, but bold/style are kept.")


# --- 6. LEVERAGING TEMPLATING ENGINES (JINJA2) ---
print_section_header("6. Leveraging Templating Engines (Jinja2)")

template_input = "<script>alert('XSS in template!');</script>"
print(f"Original input for template: {template_input}")

# SECURE: Jinja2 with autoescape=True (the default) automatically encodes variables.
env = Environment(autoescape=True)
template = env.from_string("<div>Hello, {{ name }}!</div>")
secure_template_output = template.render(name=template_input)

print(f"\n[SECURE]   Jinja2 rendered output with autoescape on:")
print(secure_template_output)

# INSECURE: Manually disabling autoescaping with `| safe` filter is dangerous.
# env_insecure = Environment(autoescape=True)
# template_insecure = env_insecure.from_string("<div>Hello, {{ name | safe }}!</div>")
# insecure_template_output = template_insecure.render(name=template_input)
# print(f"\n[INSECURE] Jinja2 rendered output with '| safe' filter:")
# print(insecure_template_output)
print("\n[INSECURE] Example using the `| safe` filter is highly discouraged and commented out.")