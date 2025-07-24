 import os
import hashlib
import hmac
import time
from http.cookies import SimpleCookie

# In-memory session store (for demonstration only! Use a proper database in production)
SESSION_STORE = {}
SESSION_COOKIE_NAME = "my_session_id"
SESSION_LIFETIME_SECONDS = 3600  # 1 hour
SECRET_KEY = os.urandom(32)  # CHANGE THIS IN PRODUCTION AND KEEP IT SECRET!

def generate_session_id():
    """Generates a cryptographically secure session ID."""
    return os.urandom(32).hex()

def create_session_signature(session_id):
    """Creates a signature for the session ID to prevent tampering."""
    return hmac.new(SECRET_KEY, session_id.encode('utf-8'), hashlib.sha256).hexdigest()

def verify_session_signature(session_id, signature):
    """Verifies the session ID signature."""
    expected_signature = create_session_signature(session_id)
    return hmac.compare_digest(expected_signature, signature)

def create_new_session(response_headers):
    """Creates a new session and sets the session cookie."""
    session_id = generate_session_id()
    signature = create_session_signature(session_id)
    SESSION_STORE[session_id] = {
        "data": {},
        "created_at": time.time(),
        "last_accessed_at": time.time(),
        "signature": signature  # Store signature to verify cookie integrity
    }

    cookie = SimpleCookie()
    cookie[SESSION_COOKIE_NAME] = f"{session_id}.{signature}"
    cookie[SESSION_COOKIE_NAME]["max-age"] = SESSION_LIFETIME_SECONDS
    cookie[SESSION_COOKIE_NAME]["httponly"] = True
    cookie[SESSION_COOKIE_NAME]["samesite"] = "Lax" # or "Strict"
    # cookie[SESSION_COOKIE_NAME]["secure"] = True # UNCOMMENT IN PRODUCTION (HTTPS)
    cookie[SESSION_COOKIE_NAME]["path"] = "/"

    # Add cookie to response headers (example)
    for morsel in cookie.values():
        response_headers.append(('Set-Cookie', morsel.OutputString()))
    print(f"[*] New session created: {session_id}")
    return session_id

def get_session(request_cookies_string):
    """Gets the current session or returns None if invalid/expired."""
    if not request_cookies_string:
        return None

    cookies = SimpleCookie()
    cookies.load(request_cookies_string)

    if SESSION_COOKIE_NAME not in cookies:
        print("[-] Session cookie not found.")
        return None

    cookie_value = cookies[SESSION_COOKIE_NAME].value
    try:
        session_id, signature = cookie_value.split('.', 1)
    except ValueError:
        print("[-] Invalid session cookie format.")
        return None # Invalid format

    if not verify_session_signature(session_id, signature):
        print(f"[-] Invalid session signature for session ID: {session_id}")
        return None # Tampered cookie

    if session_id not in SESSION_STORE:
        print(f"[-] Session ID {session_id} not found in store (possibly expired or invalid).")
        return None # Session doesn't exist on server

    session_data = SESSION_STORE[session_id]

    # Check signature stored on server-side (additional integrity check)
    if not hmac.compare_digest(session_data.get("signature", ""), signature):
        print(f"[-] Server-side signature mismatch for session ID: {session_id}")
        # Potentially a compromised server-side store or logic error
        # Invalidate session
        destroy_session(session_id, []) # Pass empty list for headers if not in response context
        return None


    # Check for absolute timeout
    if (time.time() - session_data["created_at"]) > SESSION_LIFETIME_SECONDS:
        print(f"[-] Session {session_id} expired (absolute timeout).")
        destroy_session(session_id, []) # Pass empty list for headers if not in response context
        return None

    # Update last accessed time (for idle timeout - not fully implemented here)
    session_data["last_accessed_at"] = time.time()
    print(f"[*] Session {session_id} accessed.")
    return session_data["data"]


def destroy_session(session_id, response_headers):
    """Destroys a session and expires the cookie."""
    if session_id in SESSION_STORE:
        del SESSION_STORE[session_id]
        print(f"[*] Session {session_id} destroyed from server store.")

    # Expire the cookie on the client side
    cookie = SimpleCookie()
    cookie[SESSION_COOKIE_NAME] = ""
    cookie[SESSION_COOKIE_NAME]["expires"] = 0 # Expire immediately
    cookie[SESSION_COOKIE_NAME]["max-age"] = 0
    cookie[SESSION_COOKIE_NAME]["httponly"] = True
    cookie[SESSION_COOKIE_NAME]["samesite"] = "Lax"
    # cookie[SESSION_COOKIE_NAME]["secure"] = True # UNCOMMENT IN PRODUCTION (HTTPS)
    cookie[SESSION_COOKIE_NAME]["path"] = "/"

    for morsel in cookie.values():
        response_headers.append(('Set-Cookie', morsel.OutputString()))
    print(f"[*] Session cookie for {session_id} expired.")


# --- Example Usage (Conceptual - depends on your web server/framework integration) ---
def handle_request(environ, start_response):
    """
    Conceptual request handler.
    'environ' would contain request details including cookies.
    'start_response' is a WSGI function to start the HTTP response.
    """
    status = '200 OK'
    response_headers = [('Content-type', 'text/plain')]
    output = b"Hello, "

    request_cookies_string = environ.get('HTTP_COOKIE', '')
    current_session_data = get_session(request_cookies_string)

    if current_session_data is None:
        # No valid session, or it expired, or tampered. Create a new one.
        # In a real app, this might happen on a login page.
        session_id = create_new_session(response_headers) # response_headers modified in place
        current_session_data = SESSION_STORE[session_id]["data"]
        current_session_data["username"] = "guest"
        current_session_data["views"] = 1
        output += b"Guest! New session started."
    else:
        username = current_session_data.get("username", "User")
        current_session_data["views"] = current_session_data.get("views", 0) + 1
        output += f"{username}! Views: {current_session_data['views']}".encode('utf-8')

        # Example: Logout
        # if environ.get('PATH_INFO') == '/logout':
        #     session_id_to_destroy = None
        #     cookies = SimpleCookie()
        #     cookies.load(request_cookies_string)
        #     if SESSION_COOKIE_NAME in cookies:
        #         try:
        #             session_id_to_destroy, _ = cookies[SESSION_COOKIE_NAME].value.split('.', 1)
        #         except ValueError:
        #             pass # Invalid cookie format
        #     if session_id_to_destroy:
        #          destroy_session(session_id_to_destroy, response_headers) # response_headers modified
        #          output = b"Logged out."


    start_response(status, response_headers)
    return [output]

# --- To run this example (very basic WSGI server) ---
# if __name__ == '__main__':
#     from wsgiref.simple_server import make_server
#
#     # Never use wsgiref.simple_server in production!
#     # Use Gunicorn, uWSGI, etc.
#     httpd = make_server('', 8000, handle_request)
#     print("Serving on port 8000...")
#     print(f"IMPORTANT: SECRET_KEY is '{SECRET_KEY.hex()}'. Change this and keep it secret in production!")
#     print("This is a conceptual example. Use a proper framework (Flask, Django) for production session management.")
#     httpd.serve_forever()