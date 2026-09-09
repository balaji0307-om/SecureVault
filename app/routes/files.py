import io
from pathlib import Path
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, abort, send_file, Response, current_app, session
)
from app.extensions import db, limiter
from app.config import Config
from app.models.file import File, Classification
from app.models.permission import FilePermission, PermissionType
from app.models.share_link import ShareLink
from app.services.encryption import EncryptionService
from app.services.file_validator import FileValidator, FileValidationError
from app.services.secure_delete import SecureDeleteService
from app.services.security_posture import SecurityPostureService
from app.services.audit_service import AuditService
from app.services.risk_engine import RiskEngine, RiskDecision
from app.models.audit_log import AuditAction, AuditStatus
from app.utils.auth import get_current_user, login_required

files_bp = Blueprint("files", __name__)

@files_bp.route("/dashboard")
@login_required
def dashboard():
    """User security overview: storage metrics, recent files, and shared items."""
    user = get_current_user()

    # Query user files
    if user.is_admin:
        owned_files = File.query.order_by(File.created_at.desc()).limit(10).all()
        total_files = File.query.count()
        total_bytes = db.session.query(db.func.sum(File.file_size)).scalar() or 0
    else:
        owned_files = File.query.filter_by(owner_id=user.id).order_by(File.created_at.desc()).limit(10).all()
        total_files = File.query.filter_by(owner_id=user.id).count()
        total_bytes = db.session.query(db.func.sum(File.file_size)).filter(File.owner_id == user.id).scalar() or 0

    # Shared files accessible by user
    shared_perms = FilePermission.query.filter_by(user_id=user.id).all()
    shared_files_count = len(shared_perms)

    # Active share links created by user
    active_links_count = ShareLink.query.filter_by(created_by_id=user.id, is_active=True).count()

    # Dynamic real-time security posture indicators
    security_posture = SecurityPostureService.get_live_posture()

    return render_template(
        "dashboard.html",
        user=user,
        owned_files=owned_files,
        total_files=total_files,
        total_bytes=total_bytes,
        shared_files_count=shared_files_count,
        active_links_count=active_links_count,
        classifications=Classification.ALL,
        security_posture=security_posture
    )

@files_bp.route("/files")

@login_required
def list_files():
    """File vault explorer with search, classification filtering, and security badges."""
    user = get_current_user()
    classification_filter = request.args.get("classification")
    search_query = request.args.get("q", "").strip()

    if user.is_admin:
        query = File.query
    else:
        # Files owned by user OR shared explicitly with user
        permitted_file_ids = db.select(FilePermission.file_id).where(FilePermission.user_id == user.id)
        query = File.query.filter((File.owner_id == user.id) | (File.id.in_(permitted_file_ids)))


    if classification_filter and classification_filter in Classification.ALL:
        query = query.filter(File.classification == classification_filter)

    if search_query:
        query = query.filter(File.original_name.ilike(f"%{search_query}%"))

    files = query.order_by(File.created_at.desc()).all()

    return render_template(
        "files.html",
        files=files,
        user=user,
        classifications=Classification.ALL,
        selected_classification=classification_filter,
        search_query=search_query
    )

@files_bp.route("/files/upload", methods=["POST"])
@login_required
def upload_file():
    """
    Secure file upload pipeline:
    1. Validation (extension, magic bytes, size).
    2. Malware & heuristic scanning (ClamAV / EICAR).
    3. SHA-256 pre-encryption digest calculation for integrity.
    4. Envelope encryption: ephemeral AES-256-GCM DEK wrapped with Master KEK.
    5. Save encrypted blob under UUID to disk outside web root.
    6. Audit logging.
    """
    user = get_current_user()

    if "file" not in request.files:
        flash("No file part in the upload request.", "danger")
        return redirect(url_for("files.list_files"))

    uploaded_file = request.files["file"]
    classification = request.form.get("classification", Classification.INTERNAL).upper()
    if classification not in Classification.ALL:
        classification = Classification.INTERNAL

    if not uploaded_file.filename or uploaded_file.filename.strip() == "":
        flash("Please select a file to upload.", "warning")
        return redirect(url_for("files.list_files"))

    try:
        raw_bytes = uploaded_file.read()

        # Step 1: Upload validation (file type, magic bytes, size limits)
        clean_name, mime_type, file_size = FileValidator.validate_upload(
            uploaded_file.filename,
            raw_bytes
        )

        # Step 1.5: Malware & Threat Scanning (EICAR, Macro, Heuristics, ClamAV)
        from app.services.malware_scanner import MalwareScanner
        scan_result = MalwareScanner.scan(raw_bytes, clean_name)
        if not scan_result.is_clean:
            quarantine_path = MalwareScanner.quarantine(raw_bytes, clean_name, scan_result.threat_name)
            AuditService.log(
                action=AuditAction.MALWARE_DETECTED,
                status=AuditStatus.BLOCKED,
                user=user,
                details=f"Malware blocked: '{clean_name}' flagged as {scan_result.threat_name}. Quarantined to {quarantine_path.name}."
            )
            flash(
                f"Security Incident: Malware detected in '{clean_name}' ({scan_result.threat_name}). "
                f"The malicious file was rejected and isolated in quarantine.",
                "danger"
            )
            return redirect(url_for("files.list_files"))

        # Step 2: Envelope Encryption (AES-256-GCM)
        envelope = EncryptionService.encrypt_file_envelope(
            raw_bytes,
            Config.MASTER_ENCRYPTION_KEY
        )

        # Step 3: Save encrypted blob to filesystem under UUID
        new_file = File(
            original_name=clean_name,
            mime_type=mime_type,
            file_size=file_size,
            sha256_hash=envelope["sha256_hash"],
            classification=classification,
            encrypted_key=envelope["encrypted_key"],
            key_nonce=envelope["key_nonce"],
            file_nonce=envelope["file_nonce"],
            owner_id=user.id
        )

        # Write ciphertext to disk
        storage_path = Config.STORAGE_DIR / new_file.storage_name
        with open(storage_path, "wb") as f:
            f.write(envelope["encrypted_blob"])

        db.session.add(new_file)
        db.session.commit()

        AuditService.log(
            action=AuditAction.FILE_UPLOADED,
            status=AuditStatus.SUCCESS,
            user=user,
            resource_type="File",
            resource_id=new_file.id,
            details=f"Uploaded '{clean_name}' ({file_size} bytes, AES-256-GCM encrypted, Classification: {classification})"
        )


        flash(f"File '{clean_name}' successfully encrypted and securely stored in vault.", "success")
        return redirect(url_for("files.list_files"))

    except FileValidationError as ve:
        AuditService.log(
            action=AuditAction.UNAUTHORIZED_ACCESS,
            status=AuditStatus.BLOCKED,
            user=user,
            details=f"File validation rejected for '{uploaded_file.filename}': {str(ve)}"
        )
        flash(f"Upload Rejected: {str(ve)}", "danger")
        return redirect(url_for("files.list_files"))
    except Exception as e:
        AuditService.log(
            action=AuditAction.FILE_UPLOADED,
            status=AuditStatus.FAILURE,
            user=user,
            details=f"Error uploading file '{uploaded_file.filename}': {str(e)}"
        )
        flash(f"An unexpected error occurred during encryption: {str(e)}", "danger")
        return redirect(url_for("files.list_files"))

@files_bp.route("/files/<file_id>/download")
@login_required
def download_file(file_id: str):
    """
    Secure file download pipeline:
    1. Access Control (IDOR check: Owner, Admin, or PermissionType.DOWNLOAD).
    2. Suspicious-activity & risk scoring check (RiskEngine).
    3. Decrypt ephemeral DEK using Master KEK.
    4. Decrypt file payload using DEK and AES-256-GCM.
    5. Re-verify SHA-256 integrity against stored upload hash.
    6. Deliver file with security headers and integrity status.
    """
    user = get_current_user()
    file = File.query.get_or_404(file_id)

    # Step 1: IDOR & Access Control Check
    has_permission = False
    if user.is_admin or file.owner_id == user.id:
        has_permission = True
    else:
        perm = FilePermission.query.filter(
            FilePermission.file_id == file.id,
            FilePermission.user_id == user.id,
            FilePermission.permission.in_([PermissionType.DOWNLOAD, PermissionType.READ])
        ).first()
        if perm:
            has_permission = True

    if not has_permission:
        AuditService.log(
            action=AuditAction.UNAUTHORIZED_ACCESS,
            status=AuditStatus.BLOCKED,
            user=user,
            resource_type="File",
            resource_id=file.id,
            details=f"IDOR Alert: User '{user.username}' attempted unauthorized download of file '{file.original_name}'"
        )
        abort(403)

    # Step 1.5: Step-Up Authorization for HIGHLY_CONFIDENTIAL assets
    if file.classification == Classification.HIGHLY_CONFIDENTIAL:
        import time
        reauth_timestamps = session.get("reauth_clearances", {})
        last_cleared = reauth_timestamps.get(file.id, 0)
        # Require re-auth if not verified within the last 300 seconds (5 minutes)
        if time.time() - last_cleared > 300:
            return redirect(url_for("files.reauth_download", file_id=file.id))

    # Step 2: Risk Engine Suspicious Activity Check
    risk_score, decision, reasons = RiskEngine.evaluate_request(
        user=user,
        target_file=file,
        action="DOWNLOAD"
    )

    if decision == RiskDecision.BLOCK:
        flash(
            f"Security Notice: Action temporarily blocked by risk engine (Risk Score: {risk_score}/100). Reasons: {'; '.join(reasons)}",
            "danger"
        )
        return redirect(url_for("files.list_files"))

    # Step 3 & 4: Envelope Decryption
    storage_path = Config.STORAGE_DIR / file.storage_name
    if not storage_path.exists():
        AuditService.log(
            action=AuditAction.FILE_DOWNLOADED,
            status=AuditStatus.FAILURE,
            user=user,
            resource_type="File",
            resource_id=file.id,
            details="Encrypted file blob missing from disk."
        )
        abort(404)

    try:
        with open(storage_path, "rb") as f:
            encrypted_blob = f.read()

        decrypted_bytes = EncryptionService.decrypt_file_envelope(
            encrypted_blob=encrypted_blob,
            encrypted_key_b64=file.encrypted_key,
            file_nonce_b64=file.file_nonce,
            key_nonce_b64=file.key_nonce,
            master_key=Config.MASTER_ENCRYPTION_KEY
        )

        # Step 5: Cryptographic Integrity Verification (SHA-256)
        is_intact = EncryptionService.verify_integrity(file.sha256_hash, decrypted_bytes)
        if not is_intact:
            AuditService.log(
                action=AuditAction.INTEGRITY_FAILED,
                status=AuditStatus.FAILURE,
                user=user,
                resource_type="File",
                resource_id=file.id,
                details=f"CRITICAL: Integrity failure on file '{file.original_name}'! SHA-256 hash mismatch."
            )
            flash("Security Warning: File integrity check failed! Blob may have been tampered with.", "danger")
            return redirect(url_for("files.list_files"))

        AuditService.log(
            action=AuditAction.FILE_DOWNLOADED,
            status=AuditStatus.SUCCESS,
            user=user,
            resource_type="File",
            resource_id=file.id,
            details=f"Downloaded '{file.original_name}' (Integrity: VERIFIED, SHA-256: {file.sha256_hash[:12]}...)"
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
            action=AuditAction.FILE_DOWNLOADED,
            status=AuditStatus.FAILURE,
            user=user,
            resource_type="File",
            resource_id=file.id,
            details=f"Decryption failed: {str(e)}"
        )
        flash(f"Decryption failed: {str(e)}", "danger")
        return redirect(url_for("files.list_files"))

@files_bp.route("/files/<file_id>/delete", methods=["POST"])
@login_required
def delete_file(file_id: str):
    """
    Secure Deletion Protocol:
    1. Check permissions (Owner, Admin, or PermissionType.DELETE).
    2. Revoke associated file permissions.
    3. Invalidate associated share links.
    4. Overwrite and erase encrypted DEK and nonces in DB.
    5. Securely shred ciphertext blob on disk (overwriting sectors before unlinking).
    6. Delete file database record.
    7. Write audit log.
    """
    user = get_current_user()
    file = File.query.get_or_404(file_id)

    # Permission check
    can_delete = False
    if user.is_admin or file.owner_id == user.id:
        can_delete = True
    else:
        perm = FilePermission.query.filter_by(
            file_id=file.id,
            user_id=user.id,
            permission=PermissionType.DELETE
        ).first()
        if perm:
            can_delete = True

    if not can_delete:
        AuditService.log(
            action=AuditAction.UNAUTHORIZED_ACCESS,
            status=AuditStatus.BLOCKED,
            user=user,
            resource_type="File",
            resource_id=file.id,
            details=f"Unauthorized deletion attempt on file '{file.original_name}'"
        )
        abort(403)

    filename = file.original_name
    SecureDeleteService.delete_file(file, user)

    flash(f"File '{filename}' deleted via 3-pass overwrite-based secure deletion for supported storage media.", "success")
    return redirect(url_for("files.list_files"))

@files_bp.route("/files/<file_id>/reauth", methods=["GET", "POST"])
@login_required
def reauth_download(file_id: str):
    """Step-up identity re-authentication challenge before downloading HIGHLY_CONFIDENTIAL assets."""
    user = get_current_user()
    file = File.query.get_or_404(file_id)

    # Verify user has access before presenting re-auth prompt
    if not user.is_admin and file.owner_id != user.id:
        perm = FilePermission.query.filter(
            FilePermission.file_id == file.id,
            FilePermission.user_id == user.id,
            FilePermission.permission.in_([PermissionType.DOWNLOAD, PermissionType.READ])
        ).first()
        if not perm:
            abort(403)

    if request.method == "POST":
        password = request.form.get("password", "")
        totp_token = request.form.get("totp_token", "").strip().replace(" ", "")

        # Verify password
        if not user.check_password(password):
            AuditService.log(
                action=AuditAction.LOGIN_FAILED,
                status=AuditStatus.FAILURE,
                user=user,
                resource_type="File",
                resource_id=file.id,
                details=f"Step-up re-authentication failed for HIGHLY_CONFIDENTIAL file '{file.original_name}' (bad password)."
            )
            flash("Re-authentication failed: incorrect password.", "danger")
            return render_template("reauth_download.html", file=file, user=user)

        # If user has 2FA enabled, also verify TOTP code
        if user.is_2fa_enabled:
            import pyotp
            totp = pyotp.TOTP(user.totp_secret)
            if not totp.verify(totp_token, valid_window=1):
                AuditService.log(
                    action=AuditAction.LOGIN_FAILED,
                    status=AuditStatus.FAILURE,
                    user=user,
                    resource_type="File",
                    resource_id=file.id,
                    details=f"Step-up re-authentication failed for file '{file.original_name}' (bad 2FA TOTP code)."
                )
                flash("Re-authentication failed: invalid 2FA code.", "danger")
                return render_template("reauth_download.html", file=file, user=user)

        # Grant 5-minute clearance for this file download
        import time
        reauth_timestamps = session.get("reauth_clearances", {})
        reauth_timestamps[file.id] = time.time()
        session["reauth_clearances"] = reauth_timestamps

        AuditService.log(
            action=AuditAction.LOGIN_SUCCESS,
            status=AuditStatus.SUCCESS,
            user=user,
            resource_type="File",
            resource_id=file.id,
            details=f"Step-up re-authentication granted for HIGHLY_CONFIDENTIAL file '{file.original_name}'."
        )
        return redirect(url_for("files.download_file", file_id=file.id))

    return render_template("reauth_download.html", file=file, user=user)

