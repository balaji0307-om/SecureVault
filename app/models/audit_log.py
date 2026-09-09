from datetime import datetime, timezone
from app.extensions import db

class AuditAction:
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    TWO_FACTOR_ENABLED = "TWO_FACTOR_ENABLED"
    
    FILE_UPLOADED = "FILE_UPLOADED"
    FILE_DOWNLOADED = "FILE_DOWNLOADED"
    FILE_DELETED = "FILE_DELETED"
    INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
    INTEGRITY_FAILED = "INTEGRITY_FAILED"
    
    SHARE_LINK_CREATED = "SHARE_LINK_CREATED"
    SHARE_LINK_ACCESSED = "SHARE_LINK_ACCESSED"
    SHARE_LINK_EXPIRED = "SHARE_LINK_EXPIRED"
    SHARE_LINK_BLOCKED = "SHARE_LINK_BLOCKED"
    
    PERMISSION_GRANTED = "PERMISSION_GRANTED"
    PERMISSION_REVOKED = "PERMISSION_REVOKED"
    
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    BRUTE_FORCE_DETECTED = "BRUTE_FORCE_DETECTED"
    SUSPICIOUS_ACTIVITY_DETECTED = "SUSPICIOUS_ACTIVITY_DETECTED"
    MALWARE_DETECTED = "MALWARE_DETECTED"
    POLICY_VIOLATION = "POLICY_VIOLATION"

class AuditStatus:
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    WARNING = "WARNING"
    BLOCKED = "BLOCKED"

class AuditSeverity:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def get_default_severity(cls, action: str, status: str = AuditStatus.SUCCESS) -> str:
        """Derive standard cybersecurity severity level based on action and outcome."""
        if action in (AuditAction.BRUTE_FORCE_DETECTED, AuditAction.MALWARE_DETECTED, AuditAction.INTEGRITY_FAILED):
            return cls.CRITICAL
        if action in (AuditAction.UNAUTHORIZED_ACCESS, AuditAction.ACCOUNT_LOCKED, AuditAction.POLICY_VIOLATION):
            return cls.HIGH
        if status == AuditStatus.BLOCKED or status == AuditStatus.FAILURE:
            return cls.HIGH
        if action in (AuditAction.SHARE_LINK_CREATED, AuditAction.PERMISSION_GRANTED, AuditAction.PERMISSION_REVOKED, AuditAction.SUSPICIOUS_ACTIVITY_DETECTED):
            return cls.MEDIUM
        if action in (AuditAction.FILE_UPLOADED, AuditAction.FILE_DOWNLOADED, AuditAction.FILE_DELETED, AuditAction.SHARE_LINK_ACCESSED):
            return cls.LOW
        return cls.INFO

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    
    # User context
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    username = db.Column(db.String(64), nullable=True)
    
    # Network & client context
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    user_agent = db.Column(db.String(255), nullable=True)
    
    # Action & resource
    action = db.Column(db.String(64), nullable=False, index=True)
    resource_type = db.Column(db.String(50), nullable=True)
    resource_id = db.Column(db.String(64), nullable=True)
    details = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default=AuditStatus.SUCCESS, nullable=False, index=True)
    severity = db.Column(db.String(20), default=AuditSeverity.INFO, nullable=False, index=True)

    # Relationships
    user = db.relationship("User", foreign_keys=[user_id])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "severity" not in kwargs or not self.severity:
            self.severity = AuditSeverity.get_default_severity(self.action, self.status)

    def __repr__(self):
        return f"<AuditLog {self.action} [{self.severity}:{self.status}] by {self.username or 'Anonymous'} at {self.timestamp}>"
