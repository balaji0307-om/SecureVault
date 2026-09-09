import csv
import io
from flask import (
    Blueprint, render_template, request, Response, abort
)
from app.extensions import db
from app.models.audit_log import AuditLog, AuditAction, AuditStatus
from app.utils.auth import get_current_user, admin_required

security_bp = Blueprint("security", __name__, url_prefix="/security")

@security_bp.route("/audit")
@admin_required
def audit_logs():
    """Security Audit Trail Explorer: filterable by action, status, and search keyword."""
    user = get_current_user()
    action_filter = request.args.get("action", "").strip()
    status_filter = request.args.get("status", "").strip()
    search_query = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)

    query = AuditLog.query

    if action_filter:
        query = query.filter(AuditLog.action == action_filter)
    if status_filter:
        query = query.filter(AuditLog.status == status_filter)
    if search_query:
        search_pattern = f"%{search_query}%"
        query = query.filter(
            (AuditLog.username.ilike(search_pattern)) |
            (AuditLog.ip_address.ilike(search_pattern)) |
            (AuditLog.details.ilike(search_pattern)) |
            (AuditLog.action.ilike(search_pattern))
        )

    pagination = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=25, error_out=False
    )

    # Distinct actions for filter dropdown
    distinct_actions = [r[0] for r in db.session.query(AuditLog.action).distinct().all()]

    return render_template(
        "audit_logs.html",
        user=user,
        logs=pagination.items,
        pagination=pagination,
        actions=distinct_actions,
        statuses=[AuditStatus.SUCCESS, AuditStatus.FAILURE, AuditStatus.WARNING, AuditStatus.BLOCKED],
        selected_action=action_filter,
        selected_status=status_filter,
        search_query=search_query
    )

@security_bp.route("/audit/export")
@admin_required
def export_audit_logs():
    """Export audit log to CSV for SIEM ingestion or compliance reporting."""
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(1000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp (UTC)", "Username", "IP Address", "User-Agent", "Action", "Status", "Resource", "Details"])

    for log in logs:
        writer.writerow([
            log.id,
            log.timestamp.isoformat(),
            log.username or "Anonymous",
            log.ip_address or "N/A",
            log.user_agent or "N/A",
            log.action,
            log.status,
            f"{log.resource_type or ''}:{log.resource_id or ''}",
            log.details or ""
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=securevault_audit_export.csv"}
    )

@security_bp.route("/risk")
@admin_required
def risk_alerts():
    """View suspicious activity and threat detection incidents."""
    user = get_current_user()
    alerts = AuditLog.query.filter(
        AuditLog.action.in_([
            AuditAction.BRUTE_FORCE_DETECTED,
            AuditAction.SUSPICIOUS_ACTIVITY_DETECTED,
            AuditAction.UNAUTHORIZED_ACCESS,
            AuditAction.MALWARE_DETECTED,
            AuditAction.INTEGRITY_FAILED,
            AuditAction.POLICY_VIOLATION
        ])
    ).order_by(AuditLog.timestamp.desc()).limit(50).all()

    return render_template("risk_alerts.html", user=user, alerts=alerts)
