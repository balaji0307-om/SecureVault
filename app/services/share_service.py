import secrets
from datetime import datetime, timezone, timedelta
from app.extensions import db
from app.models.file import File, Classification
from app.models.share_link import ShareLink
from app.services.audit_service import AuditService
from app.models.audit_log import AuditAction, AuditStatus

class SharePolicyViolationError(Exception):
    """Raised when sharing policy is violated (e.g. attempting to share HIGHLY_CONFIDENTIAL publicly)."""
    pass

class ShareService:
    """Service to generate, validate, and enforce Zero-Trust access policies on share links."""

    @classmethod
    def generate_token(cls) -> str:
        """Generate a cryptographically secure 256-bit URL-safe token."""
        return secrets.token_urlsafe(32)

    @classmethod
    def create_share_link(
        cls,
        file: File,
        user,
        expiry_hours: int = 24,
        max_downloads: int = 0,
        password: str = None,
        is_one_time: bool = False
    ) -> ShareLink:
        """
        Create a new expiring, signed share link.
        ENFORCES POLICY: HIGHLY_CONFIDENTIAL files cannot have public share links.
        """
        # Policy Enforcement
        if file.classification == Classification.HIGHLY_CONFIDENTIAL:
            AuditService.log(
                action=AuditAction.POLICY_VIOLATION,
                status=AuditStatus.BLOCKED,
                user=user,
                resource_type="File",
                resource_id=file.id,
                details="Attempted to create public share link for HIGHLY_CONFIDENTIAL file."
            )
            raise SharePolicyViolationError(
                "Policy Denied: HIGHLY_CONFIDENTIAL files cannot be shared via public links. "
                "Use direct explicit user permissions instead."
            )

        token = cls.generate_token()
        expires_at = None
        if expiry_hours and expiry_hours > 0:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)

        share_link = ShareLink(
            file_id=file.id,
            token=token,
            expires_at=expires_at,
            max_downloads=1 if is_one_time else max_downloads,
            is_one_time=is_one_time,
            created_by_id=user.id,
            is_active=True
        )

        if password:
            share_link.set_password(password)

        db.session.add(share_link)
        db.session.commit()

        AuditService.log(
            action=AuditAction.SHARE_LINK_CREATED,
            status=AuditStatus.SUCCESS,
            user=user,
            resource_type="ShareLink",
            resource_id=share_link.id,
            details=f"Token created for file '{file.original_name}' (OneTime: {is_one_time}, MaxDownloads: {max_downloads}, Expiry: {expiry_hours}h)"
        )

        return share_link

    @classmethod
    def get_link_or_error(cls, token: str) -> tuple[ShareLink | None, str | None]:
        """
        Retrieve and validate a share link.
        Returns: (share_link, error_string)
        """
        link = ShareLink.query.filter_by(token=token).first()
        if not link:
            return None, "Share link not found or invalid."

        if not link.is_active:
            if link.is_one_time and link.download_count >= 1:
                return None, "LINK ALREADY USED (One-time link has been consumed)."
            return None, "This share link is no longer active."

        if link.is_expired():
            link.is_active = False
            db.session.commit()
            AuditService.log(
                action=AuditAction.SHARE_LINK_EXPIRED,
                status=AuditStatus.WARNING,
                resource_type="ShareLink",
                resource_id=link.id,
                details=f"Access denied: Link expired at {link.expires_at}"
            )
            return None, "This share link has expired."

        if link.is_exhausted():
            link.is_active = False
            db.session.commit()
            if link.is_one_time:
                return None, "LINK ALREADY USED (One-time link has been consumed)."
            return None, "Maximum download limit reached for this share link."

        return link, None
