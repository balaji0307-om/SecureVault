from datetime import datetime, timezone, timedelta
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, abort
)
from app.extensions import db
from app.models.user import User
from app.models.file import File
from app.models.share_link import ShareLink
from app.models.audit_log import AuditLog, AuditAction, AuditStatus
from app.services.audit_service import AuditService
from app.utils.auth import get_current_user, admin_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.route("")
@admin_bp.route("/")
@admin_required
def dashboard():
    """Admin Security Dashboard: Key Metrics & Real-Time Event Stream."""
    user = get_current_user()
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)

    # Core Security Metrics
    total_users = User.query.count()
    total_files = File.query.count()
    total_bytes = db.session.query(db.func.sum(File.file_size)).scalar() or 0
    active_links = ShareLink.query.filter_by(is_active=True).count()

    failed_logins_24h = AuditLog.query.filter(
        AuditLog.action == AuditAction.LOGIN_FAILED,
        AuditLog.timestamp >= last_24h
    ).count()

    blocked_requests_24h = AuditLog.query.filter(
        AuditLog.status == AuditStatus.BLOCKED,
        AuditLog.timestamp >= last_24h
    ).count()

    security_alerts_count = AuditLog.query.filter(
        AuditLog.action.in_([
            AuditAction.BRUTE_FORCE_DETECTED,
            AuditAction.UNAUTHORIZED_ACCESS,
            AuditAction.SUSPICIOUS_ACTIVITY_DETECTED,
            AuditAction.MALWARE_DETECTED,
            AuditAction.INTEGRITY_FAILED,
            AuditAction.POLICY_VIOLATION
        ])
    ).count()

    # Derive live Risk Level from recent threat events and risk scores
    threat_events_24h = AuditLog.query.filter(
        AuditLog.action.in_([
            AuditAction.BRUTE_FORCE_DETECTED,
            AuditAction.UNAUTHORIZED_ACCESS,
            AuditAction.SUSPICIOUS_ACTIVITY_DETECTED,
            AuditAction.INTEGRITY_FAILED,
            AuditAction.POLICY_VIOLATION
        ]),
        AuditLog.timestamp >= last_24h
    ).count()

    if threat_events_24h >= 5:
        risk_level = "HIGH"
        risk_badge_class = "danger"
    elif threat_events_24h >= 1:
        risk_level = "MEDIUM"
        risk_badge_class = "warning"
    else:
        risk_level = "LOW"
        risk_badge_class = "success"

    # Recent Security Events (Live, unmocked audit trail)
    recent_events = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(15).all()

    # System Users
    users = User.query.order_by(User.created_at.desc()).limit(10).all()

    return render_template(
        "admin.html",
        user=user,
        total_users=total_users,
        total_files=total_files,
        total_bytes=total_bytes,
        active_links=active_links,
        failed_logins_24h=failed_logins_24h,
        blocked_requests_24h=blocked_requests_24h,
        security_alerts_count=security_alerts_count,
        risk_level=risk_level,
        risk_badge_class=risk_badge_class,
        recent_events=recent_events,
        users=users
    )


@admin_bp.route("/users")
@admin_required
def list_users():
    """User Management: Account lockouts, role elevation, and active statuses."""
    user = get_current_user()
    users = User.query.order_by(User.id.asc()).all()
    return render_template("admin_users.html", user=user, users=users)

@admin_bp.route("/users/<int:user_id>/unlock", methods=["POST"])
@admin_required
def unlock_user(user_id: int):
    """Manually clear account lockout for a user."""
    admin = get_current_user()
    target_user = User.query.get_or_404(user_id)

    target_user.reset_lockout()
    db.session.commit()

    AuditService.log(
        action="USER_UNLOCKED",
        status=AuditStatus.SUCCESS,
        user=admin,
        details=f"Admin '{admin.username}' unlocked account for '{target_user.username}'."
    )
    flash(f"Account for '{target_user.username}' has been unlocked.", "success")
    return redirect(url_for("admin.list_users"))

@admin_bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@admin_required
def toggle_user_active(user_id: int):
    """Activate or deactivate user account."""
    admin = get_current_user()
    target_user = User.query.get_or_404(user_id)

    if target_user.id == admin.id:
        flash("You cannot deactivate your own administrative account.", "warning")
        return redirect(url_for("admin.list_users"))

    target_user.is_active = not target_user.is_active
    db.session.commit()

    status_str = "activated" if target_user.is_active else "deactivated"
    AuditService.log(
        action="USER_STATUS_MODIFIED",
        status=AuditStatus.SUCCESS,
        user=admin,
        details=f"Admin '{admin.username}' {status_str} account for '{target_user.username}'."
    )
    flash(f"User '{target_user.username}' has been {status_str}.", "info")
    return redirect(url_for("admin.list_users"))

@admin_bp.route("/users/<int:user_id>/change-role", methods=["POST"])
@admin_required
def change_user_role(user_id: int):
    """Change user role between USER and ADMIN."""
    admin = get_current_user()
    target_user = User.query.get_or_404(user_id)
    new_role = request.form.get("role", "USER").upper()

    if target_user.id == admin.id and new_role != "ADMIN":
        flash("You cannot remove admin privileges from your own account.", "warning")
        return redirect(url_for("admin.list_users"))

    if new_role in ("ADMIN", "USER"):
        old_role = target_user.role
        target_user.role = new_role
        db.session.commit()

        AuditService.log(
            action="ROLE_CHANGED",
            status=AuditStatus.SUCCESS,
            user=admin,
            details=f"Admin '{admin.username}' changed role of '{target_user.username}' from {old_role} to {new_role}."
        )
        flash(f"Role for '{target_user.username}' updated to {new_role}.", "success")

    return redirect(url_for("admin.list_users"))
