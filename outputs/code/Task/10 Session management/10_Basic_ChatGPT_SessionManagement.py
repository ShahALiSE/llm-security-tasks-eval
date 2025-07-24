import uuid
import time

class Session:
    def __init__(self, user_id, timeout=300):
        self.session_id = str(uuid.uuid4())
        self.user_id = user_id
        self.created_at = time.time()
        self.last_active = self.created_at
        self.timeout = timeout  # session lifetime in seconds

    def is_expired(self):
        return (time.time() - self.last_active) > self.timeout

    def refresh(self):
        self.last_active = time.time()

class SessionManager:
    def __init__(self):
        self.sessions = {}  # session_id -> Session object

    def create_session(self, user_id):
        session = Session(user_id)
        self.sessions[session.session_id] = session
        return session.session_id

    def get_session(self, session_id):
        session = self.sessions.get(session_id)
        if session and not session.is_expired():
            session.refresh()
            return session
        elif session:
            self.destroy_session(session_id)
        return None

    def is_valid(self, session_id):
        return self.get_session(session_id) is not None

    def destroy_session(self, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]

    def cleanup_expired_sessions(self):
        expired = [sid for sid, session in self.sessions.items() if session.is_expired()]
        for sid in expired:
            self.destroy_session(sid)

# Example usage
if __name__ == "__main__":
    manager = SessionManager()
    sid = manager.create_session("user_42")
    print(f"Session created: {sid}")

    time.sleep(2)
    if manager.is_valid(sid):
        print("Session is valid and refreshed.")
    else:
        print("Session expired or invalid.")

    time.sleep(301)
    manager.cleanup_expired_sessions()
    print("Expired sessions cleaned up.")
