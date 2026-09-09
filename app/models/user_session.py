import hashlib
from datetime import datetime, timezone
from app.extensions import db

class UserSession(db.Model):
    """
    Model representing an active authenticated session for concurrent session
    tracking, remote device revocation, and session rotation.
    """
    __tablename__ = "user_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    session_token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    device_name = db.Column(db.String(100), default="Web Browser", nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_active_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    is_revoked = db.Column(db.Boolean, default=False, nullable=False, index=True)

    # Relationships
    user = db.relationship("User", backref=db.backref("sessions", cascade="all, delete-orphan", lazy="dynamic"))

    @staticmethod
    def hash_token(raw_token: str) -> str:
        """Hash the session token using SHA-256 before database storage."""
        return hashlib.sha256(raw_token.encode()).hexdigest()

    @staticmethod
    def parse_device_name(ua_string: str) -> str:
        """Derive readable device and browser label from User-Agent string."""
        if not ua_string:
            return "Unknown Device"
        ua = ua_string.lower()

        # OS detection
        os_label = "Unknown OS"
        if "windows" in ua:
            os_label = "Windows"
        elif "macintosh" in ua or "mac os" in ua:
            os_label = "macOS"
        elif "linux" in ua:
            os_label = "Linux"
        elif "android" in ua:
            os_label = "Android"
        elif "iphone" in ua or "ipad" in ua:
            os_label = "iOS"

        # Browser detection
        browser_label = "Browser"
        if "edg" in ua:
            browser_label = "Edge"
        elif "chrome" in ua or "crios" in ua:
            browser_label = "Chrome"
        elif "firefox" in ua or "fxios" in ua:
            browser_label = "Firefox"
        elif "safari" in ua:
            browser_label = "Safari"

        return f"{browser_label} on {os_label}"

    def revoke(self) -> None:
        """Mark this session as revoked."""
        self.is_revoked = True

    def __repr__(self):
        return f"<UserSession user_id={self.user_id} device={self.device_name} revoked={self.is_revoked}>"
