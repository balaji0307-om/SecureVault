from datetime import datetime, timezone, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from app.extensions import db

ph = PasswordHasher(
    time_cost=3,        # Iterations
    memory_cost=65536,  # 64 MB
    parallelism=4,      # 4 lanes
    hash_len=32,
    salt_len=16
)

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="USER", nullable=False)  # "USER" or "ADMIN"
    totp_secret = db.Column(db.String(64), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False, nullable=False)

    # Brute-force lockout fields
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    files = db.relationship("File", back_populates="owner", cascade="all, delete-orphan")
    permissions = db.relationship("FilePermission", back_populates="user", cascade="all, delete-orphan", foreign_keys="FilePermission.user_id")
    share_links = db.relationship("ShareLink", back_populates="creator", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        """Hash password using Argon2id with memory-hard parameters."""
        self.password_hash = ph.hash(password)

    def check_password(self, password: str) -> bool:
        """Verify password against Argon2 hash with constant-time check."""
        try:
            ph.verify(self.password_hash, password)
            if ph.check_needs_rehash(self.password_hash):
                self.password_hash = ph.hash(password)
                db.session.commit()
            return True
        except (VerifyMismatchError, VerificationError):
            return False

    def is_locked(self) -> bool:
        """Check if account is temporarily locked due to brute-force attempts."""
        if self.locked_until:
            now = datetime.now(timezone.utc)
            # Handle tz-aware and tz-naive datetime comparisons safely
            locked_at = self.locked_until
            if locked_at.tzinfo is None:
                locked_at = locked_at.replace(tzinfo=timezone.utc)
            if now < locked_at:
                return True
            else:
                # Lockout expired; reset counter
                self.reset_lockout()
                db.session.commit()
        return False

    def increment_failed_attempts(self, max_attempts: int = 5, lockout_minutes: int = 15) -> bool:
        """Increment failed attempts and lock account if threshold exceeded. Returns True if locked."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_attempts:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
            return True
        return False

    def reset_lockout(self) -> None:
        """Reset failed login attempts and clear lockout timestamp."""
        self.failed_login_attempts = 0
        self.locked_until = None

    @property
    def is_admin(self) -> bool:
        return self.role == "ADMIN"

    def __repr__(self):
        return f"<User {self.username} (Role: {self.role})>"
