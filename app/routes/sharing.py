import io
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, abort, send_file, session
)
from app.extensions import db, limiter
from app.config import Config
from app.models.user import User
from app.models.file import File, Classification
from app.models.permission import FilePermission, PermissionType
from app.models.share_link import ShareLink
from app.services.encryption import EncryptionService
from app.services.share_service import ShareService, SharePolicyViolationError
from app.services.audit_service import AuditService
from app.models.audit_log import AuditAction, AuditStatus
from app.utils.auth import get_current_user, login_required

sharing_bp = Blueprint("sharing", __name__)

@sharing_bp.route("/files/<file_id>/share", methods=["GET"])
@login_required
def manage_sharing(file_id: str):
    """View and configure share links and fine-grained user permissions."""
    user = get_current_user()
    file = File.query.get_or_404(file_id)

    # Check access: Owner, Admin, or RESHARE permission
    can_share = False
    if user.is_admin or file.owner_id == user.id:
        can_share = True
    else:
        perm = FilePermission.query.filter_by(
            file_id=file.id,
            user_id=user.id,
            permission=PermissionType.RESHARE
        ).first()
        if perm:
            can_share = True

    if not can_share:
        AuditService.log(
            action=AuditAction.UNAUTHORIZED_ACCESS,
            status=AuditStatus.BLOCKED,
            user=user,
            resource_type="File",
            resource_id=file.id,
            details="User lacks RESHARE permission."
        )
        abort(403)

    active_links = ShareLink.query.filter_by(file_id=file.id, is_active=True).all()
    user_permissions = FilePermission.query.filter_by(file_id=file.id).all()
    available_users = User.query.filter(User.id != file.owner_id, User.is_active == True).all()

    return render_template(
        "share.html",
        file=file,
        user=user,
        active_links=active_links,
        user_permissions=user_permissions,
        available_users=available_users,
        permission_types=PermissionType.ALL
    )

@sharing_bp.route("/files/<file_id>/share/link", methods=["POST"])
@login_required
def create_link(file_id: str):
    """Generate an expiring, signed share link with download limits and password."""
    user = get_current_user()
    file = File.query.get_or_404(file_id)

    if not (user.is_admin or file.owner_id == user.id):
        abort(403)

    try:
        expiry_hours = int(request.form.get("expiry_hours", 24))
        max_downloads = int(request.form.get("max_downloads", 0))
        password = request.form.get("password", "").strip() or None
        is_one_time = bool(request.form.get("is_one_time"))

        link = ShareService.create_share_link(
            file=file,
            user=user,
            expiry_hours=expiry_hours,
            max_downloads=max_downloads,
            password=password,
            is_one_time=is_one_time
        )

        share_url = url_for("sharing.access_share_link", token=link.token, _external=True)
        flash(f"Secure share link created! URL: {share_url}", "success")
        return redirect(url_for("sharing.manage_sharing", file_id=file.id))

    except SharePolicyViolationError as pe:
        flash(str(pe), "danger")
        return redirect(url_for("sharing.manage_sharing", file_id=file.id))
    except Exception as e:
        flash(f"Failed to create share link: {str(e)}", "danger")
        return redirect(url_for("sharing.manage_sharing", file_id=file.id))

@sharing_bp.route("/files/<file_id>/share/permission", methods=["POST"])
@login_required
def grant_permission(file_id: str):
    """Grant fine-grained file permission to a specific user (RBAC)."""
    user = get_current_user()
    file = File.query.get_or_404(file_id)

    if not (user.is_admin or file.owner_id == user.id):
        abort(403)

    target_user_id = request.form.get("target_user_id", type=int)
    permission = request.form.get("permission", "").upper()

    if not target_user_id or permission not in PermissionType.ALL:
        flash("Invalid user or permission selected.", "warning")
        return redirect(url_for("sharing.manage_sharing", file_id=file.id))

    target_user = User.query.get(target_user_id)
    if not target_user:
        flash("Target user not found.", "warning")
        return redirect(url_for("sharing.manage_sharing", file_id=file.id))

    # Check if permission already exists
    existing = FilePermission.query.filter_by(
        file_id=file.id,
        user_id=target_user.id,
        permission=permission
    ).first()

    if existing:
        flash(f"User '{target_user.username}' already has {permission} permission on this file.", "info")
    else:
        new_perm = FilePermission(
            file_id=file.id,
            user_id=target_user.id,
            permission=permission,
            granted_by_id=user.id
        )
        db.session.add(new_perm)
        db.session.commit()

        AuditService.log(
            action=AuditAction.PERMISSION_GRANTED,
            status=AuditStatus.SUCCESS,
            user=user,
            resource_type="File",
            resource_id=file.id,
            details=f"Granted {permission} permission to '{target_user.username}' on file '{file.original_name}'"
        )
        flash(f"Permission {permission} granted to {target_user.username}.", "success")

    return redirect(url_for("sharing.manage_sharing", file_id=file.id))

@sharing_bp.route("/files/<file_id>/share/revoke-permission/<int:perm_id>", methods=["POST"])
@login_required
def revoke_permission(file_id: str, perm_id: int):
    """Revoke a previously granted file permission."""
    user = get_current_user()
    file = File.query.get_or_404(file_id)

    if not (user.is_admin or file.owner_id == user.id):
        abort(403)

    perm = FilePermission.query.get_or_404(perm_id)
    target_username = perm.user.username
    permission_name = perm.permission

    db.session.delete(perm)
    db.session.commit()

    AuditService.log(
        action=AuditAction.PERMISSION_REVOKED,
        status=AuditStatus.SUCCESS,
        user=user,
        resource_type="File",
        resource_id=file.id,
        details=f"Revoked {permission_name} permission from '{target_username}'"
    )
    flash(f"Revoked {permission_name} permission from {target_username}.", "info")
    return redirect(url_for("sharing.manage_sharing", file_id=file.id))

@sharing_bp.route("/files/<file_id>/share/revoke-link/<link_id>", methods=["POST"])
@login_required
def revoke_link(file_id: str, link_id: str):
    """Revoke and deactivate a share link immediately."""
    user = get_current_user()
    file = File.query.get_or_404(file_id)

    if not (user.is_admin or file.owner_id == user.id):
        abort(403)

    link = ShareLink.query.get_or_404(link_id)
    link.is_active = False
    db.session.commit()

    AuditService.log(
        action=AuditAction.SHARE_LINK_EXPIRED,
        status=AuditStatus.SUCCESS,
        user=user,
        resource_type="ShareLink",
        resource_id=link.id,
        details="Share link manually revoked by file owner."
    )
    flash("Share link has been revoked and deactivated.", "info")
    return redirect(url_for("sharing.manage_sharing", file_id=file.id))

# ==============================================================================
# PUBLIC / PROTECTED SHARE LINK ACCESS ROUTES
# ==============================================================================

@sharing_bp.route("/s/<token>", methods=["GET", "POST"])
@limiter.limit("30/minute")
def access_share_link(token: str):
    """
    Landing page for accessing a shared file:
    - Validates token active status, expiration, and download limits.
    - Handles password challenge if enabled.
    - Displays one-time link alert ("LINK ALREADY USED" if burned).
    """
    link, error_msg = ShareService.get_link_or_error(token)
    if error_msg:
        AuditService.log(
            action=AuditAction.UNAUTHORIZED_ACCESS,
            status=AuditStatus.WARNING,
            resource_type="ShareLink",
            details=f"Invalid share link access ({error_msg}) for token {token[:8]}..."
        )
        return render_template("share_access.html", error=error_msg, link=None)

    file = link.file

    # Password challenge check
    requires_password = bool(link.password_hash)
    password_verified = session.get(f"share_unlocked_{link.id}", False)

    if requires_password and not password_verified:
        if request.method == "POST":
            entered_password = request.form.get("password", "")
            if link.check_password(entered_password):
                session[f"share_unlocked_{link.id}"] = True
                password_verified = True
                flash("Password verified successfully.", "success")
            else:
                AuditService.log(
                    action=AuditAction.LOGIN_FAILED,
                    status=AuditStatus.FAILURE,
                    resource_type="ShareLink",
                    resource_id=link.id,
                    details="Incorrect password entered for protected share link."
                )
                flash("Incorrect password for this share link.", "danger")

    return render_template(
        "share_access.html",
        link=link,
        file=file,
        requires_password=requires_password,
        password_verified=password_verified,
        error=None
    )

@sharing_bp.route("/s/<token>/download", methods=["GET", "POST"])
@limiter.limit("15/minute")
def download_shared_file(token: str):
    """
    Execute download for shared file:
    - Verifies link validity and password verification.
    - Decrypts envelope using AES-256-GCM.
    - Cryptographically verifies SHA-256 integrity.
    - Records download count and burns one-time links immediately.
    """
    link, error_msg = ShareService.get_link_or_error(token)
    if error_msg:
        return render_template("share_access.html", error=error_msg, link=None)

    # If password protected, ensure password was verified in session or submitted
    if link.password_hash and not session.get(f"share_unlocked_{link.id}", False):
        entered_password = request.form.get("password", "")
        if not link.check_password(entered_password):
            flash("Password verification required.", "danger")
            return redirect(url_for("sharing.access_share_link", token=token))

    file = link.file
    storage_path = Config.STORAGE_DIR / file.storage_name

    if not storage_path.exists():
        AuditService.log(
            action=AuditAction.FILE_DOWNLOADED,
            status=AuditStatus.FAILURE,
            resource_type="File",
            resource_id=file.id,
            details="Encrypted file blob missing from disk."
        )
        return render_template("share_access.html", error="Encrypted file blob not found on server.", link=None)

    try:
        with open(storage_path, "rb") as f:
            encrypted_blob = f.read()

        # Decrypt envelope
        decrypted_bytes = EncryptionService.decrypt_file_envelope(
            encrypted_blob=encrypted_blob,
            encrypted_key_b64=file.encrypted_key,
            file_nonce_b64=file.file_nonce,
            key_nonce_b64=file.key_nonce,
            master_key=Config.MASTER_ENCRYPTION_KEY
        )

        # Integrity check
        if not EncryptionService.verify_integrity(file.sha256_hash, decrypted_bytes):
            AuditService.log(
                action=AuditAction.INTEGRITY_FAILED,
                status=AuditStatus.FAILURE,
                resource_type="File",
                resource_id=file.id,
                details="SHA-256 integrity failure during shared file download!"
            )
            return render_template("share_access.html", error="File integrity check failed. Blob compromised.", link=None)

        # Record download (burns one-time link)
        link.record_download()
        db.session.commit()

        AuditService.log(
            action=AuditAction.SHARE_LINK_ACCESSED,
            status=AuditStatus.SUCCESS,
            resource_type="ShareLink",
            resource_id=link.id,
            details=f"Shared file '{file.original_name}' downloaded (Download #{link.download_count}, OneTime: {link.is_one_time})"
        )

        response = send_file(
            io.BytesIO(decrypted_bytes),
            mimetype=file.mime_type,
            as_attachment=True,
            download_name=file.original_name
        )
        response.headers["X-File-Integrity"] = "VERIFIED"
        response.headers["X-File-SHA256"] = file.sha256_hash
        return response

    except Exception as e:
        AuditService.log(
            action=AuditAction.SHARE_LINK_ACCESSED,
            status=AuditStatus.FAILURE,
            resource_type="ShareLink",
            resource_id=link.id,
            details=f"Shared download decryption error: {str(e)}"
        )
        return render_template("share_access.html", error=f"Decryption error: {str(e)}", link=None)
