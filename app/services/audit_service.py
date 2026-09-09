import sys
from datetime import datetime, timezone
from flask import request, has_request_context
from app.extensions import db
from app.models.audit_log import AuditLog, AuditAction, AuditStatus

class AuditService:
    """Centralized security audit logger for compliance and intrusion tracking."""

    @classmethod
    def log(
        cls,
        action: str,
        status: str = AuditStatus.SUCCESS,
        user=None,
        resource_type: str = None,
        resource_id: str = None,
        details: str = None,
        severity: str = None,
        commit: bool = True
    ) -> AuditLog:
        """
        Record a security event into the immutable audit trail.
        Captures IP address and User-Agent from active Flask request context.
        """
        ip_address = None
        user_agent = None

        if has_request_context():
            # Get client real IP (respecting reverse proxies if configured)
            if request.headers.get("X-Forwarded-For"):
                ip_address = request.headers.get("X-Forwarded-For").split(",")[0].strip()
            else:
                ip_address = request.remote_addr
            
            user_agent = request.headers.get("User-Agent", "")[:255]

        # Resolve user context
        user_id = getattr(user, "id", None) if user else None
        username = getattr(user, "username", None) if user else None

        try:
            log_entry = AuditLog(
                timestamp=datetime.now(timezone.utc),
                user_id=user_id,
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
                status=status,
                severity=severity
            )
            db.session.add(log_entry)
            if commit:
                db.session.commit()
            return log_entry
        except Exception as e:
            # Audit logging failure must not crash the whole application, but must be reported
            sys.stderr.write(f"[AUDIT LOGGING FAILURE] Action: {action}, Error: {str(e)}\n")
            try:
                db.session.rollback()
            except Exception:
                pass
            return None
