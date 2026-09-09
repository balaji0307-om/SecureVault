import uuid
from datetime import datetime, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from app.extensions import db

ph = PasswordHasher(time_cost=2, memory_cost=32768, parallelism=2)

class ShareLink(db.Model):
    __tablename__ = "share_links"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id = db.Column(db.String(36), db.ForeignKey("files.id", ondelete="CASCADE"), nullable=False, index=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    
    expires_at = db.Column(db.DateTime, nullable=True)
    max_downloads = db.Column(db.Integer, default=0, nullable=False)  # 0 means unlimited (until expiry)
    download_count = db.Column(db.Integer, default=0, nullable=False)
    
    password_hash = db.Column(db.String(255), nullable=True)
    is_one_time = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    file = db.relationship("File", back_populates="share_links")
    creator = db.relationship("User", back_populates="share_links")

    def set_password(self, password: str) -> None:
        """Hash share link password using Argon2."""
        if password:
            self.password_hash = ph.hash(password)
        else:
            self.password_hash = None

    def check_password(self, password: str) -> bool:
        """Verify share link password."""
        if not self.password_hash:
            return True
        if not password:
            return False
        try:
            ph.verify(self.password_hash, password)
            return True
        except (VerifyMismatchError, VerificationError):
            return False

    def is_expired(self) -> bool:
        """Check if the share link has passed its expiration time."""
        if self.expires_at:
            now = datetime.now(timezone.utc)
            expiry = self.expires_at
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            return now >= expiry
        return False

    def is_exhausted(self) -> bool:
        """Check if max download count or one-time limit is reached."""
        if self.is_one_time and self.download_count >= 1:
            return True
        if self.max_downloads > 0 and self.download_count >= self.max_downloads:
            return True
        return False

    @property
    def is_valid(self) -> bool:
        """Determine if share link is active and valid for access."""
        return self.is_active and not self.is_expired() and not self.is_exhausted()

    def record_download(self) -> None:
        """Increment download counter and deactivate one-time links immediately."""
        self.download_count += 1
        if self.is_one_time or (self.max_downloads > 0 and self.download_count >= self.max_downloads):
            self.is_active = False

    def __repr__(self):
        return f"<ShareLink Token:{self.token[:8]}... File:{self.file_id} Active:{self.is_active}>"
