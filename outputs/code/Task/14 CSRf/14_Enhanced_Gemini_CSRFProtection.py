import os
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
import secrets

# In-memory session store (for demonstration purposes)
SESSIONS = {}

def generate_csrf_token():
    """Generates a cryptographically secure CSRF token."""
    return secrets.token_hex(32)

def app(environ, start_response):
    """A simple WSGI application with CSRF protection."""
    request_method = environ.get('REQUEST_METHOD')
    path = environ.get('PATH_INFO', '/')
    headers = []
    
    # Simple session management using cookies
    cookie_header = environ.get('HTTP_COOKIE')
    cookie = SimpleCookie(cookie_header)
    session_id = cookie.get('session_id', {}).value
    
    if not session_id or session_id not in SESSIONS:
        session_id = secrets.token_hex(16)
        SESSIONS[session_id] = {}
    
    session = SESSIONS[session_id]
    
    # Set session cookie in response
    headers.append(('Set-Cookie', f'session_id={session_id}; Path=/; HttpOnly; SameSite=Lax'))

    if request_method == 'GET' and path == '/':
        # Generate and store CSRF token on GET request to the form page
        csrf_token = generate_csrf_token()
        session['csrf_token'] = csrf_token
        
        status = '200 OK'
        headers.append(('Content-type', 'text/html'))
        response_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>CSRF Protection Example</title>
                <meta name="csrf-token" content="{csrf_token}">
            </head>
            <body>
                <h2>Submit a Form (Protected by CSRF Token)</h2>
                <form action="/submit" method="post">
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <label for="data">Enter some data:</label>
                    <input type="text" id="data" name="data">
                    <button type="submit">Submit</button>
                </form>

                <h2>Submit via AJAX</h2>
                <button onclick="submitAjax()">Submit with AJAX</button>

                <script>
                    function submitAjax() {{
                        const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
                        fetch('/submit_ajax', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json',
                                'X-CSRF-Token': csrfToken
                            }},
                            body: JSON.stringify({{ data: 'some ajax data' }})
                        }})
                        .then(response => response.text())
                        .then(data => alert(data))
                        .catch(error => console.error('Error:', error));
                    }}
                </script>
            </body>
            </html>
        """.encode('utf-8')
    
    elif request_method == 'POST' and (path == '/submit' or path == '/submit_ajax'):
        # Validate Origin/Referer headers for an extra layer of security
        origin = environ.get('HTTP_ORIGIN')
        referer = environ.get('HTTP_REFERER')
        
        # A simple check; in production, you would have a list of allowed origins
        if not origin or 'localhost' not in origin:
            if not referer or 'localhost' not in referer:
                status = '403 Forbidden'
                response_body = b"Forbidden: Invalid Origin/Referer"
                headers.append(('Content-type', 'text/plain'))
                start_response(status, headers)
                return [response_body]

        stored_token = session.get('csrf_token')
        
        if path == '/submit':
            # For form submissions
            content_length = int(environ.get('CONTENT_LENGTH', 0))
            post_data = environ['wsgi.input'].read(content_length).decode('utf-8')
            form_data = parse_qs(post_data)
            submitted_token = form_data.get('csrf_token', [None])[0]
        else: # /submit_ajax
            # For AJAX requests from a custom header
            submitted_token = environ.get('HTTP_X_CSRF_TOKEN')
            
        if not stored_token or not submitted_token or not secrets.compare_digest(stored_token, submitted_token):
            status = '403 Forbidden'
            response_body = b"Forbidden: Invalid CSRF token."
        else:
            status = '200 OK'
            response_body = b"Success: CSRF token is valid!"
        
        headers.append(('Content-type', 'text/plain'))

    else:
        status = '404 Not Found'
        headers.append(('Content-type', 'text/plain'))
        response_body = b'Not Found'

    start_response(status, headers)
    return [response_body]

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    httpd = make_server('', 8000, app)
    print("Serving on port 8000...")
    httpd.serve_forever()