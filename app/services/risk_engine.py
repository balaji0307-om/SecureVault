from datetime import datetime, timezone, timedelta
from flask import request, has_request_context
from app.models.audit_log import AuditLog, AuditAction, AuditStatus
from app.models.file import Classification
from app.services.audit_service import AuditService

class RiskDecision:
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "TEMPORARILY BLOCKED"

class RiskEngine:
    """
    Rule-based heuristic risk engine for detecting abnormal download spikes,
    geographic/IP anomalies, and high-frequency access patterns.
    """

    RISK_THRESHOLD_BLOCK = 70
    RISK_THRESHOLD_WARN = 40

    @classmethod
    def evaluate_request(
        cls,
        user=None,
        target_file=None,
        action: str = "DOWNLOAD"
    ) -> tuple[int, str, list[str]]:
        """
        Evaluate current request context against security risk rules.
        Returns: (risk_score: int, decision: str, reasons: list[str])
        """
        score = 0
        reasons = []

        now = datetime.now(timezone.utc)
        user_id = getattr(user, "id", None) if user else None

        client_ip = None
        user_agent = None
        if has_request_context():
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            if client_ip:
                client_ip = client_ip.split(",")[0].strip()
            user_agent = request.headers.get("User-Agent", "")

        # Rule 1: High download volume / velocity in a short window (2 minutes)
        if action in ("DOWNLOAD", "FILE_DOWNLOADED") and (user_id or client_ip):
            window_start = now - timedelta(minutes=2)
            query = AuditLog.query.filter(
                AuditLog.action.in_([AuditAction.FILE_DOWNLOADED, AuditAction.SHARE_LINK_ACCESSED]),
                AuditLog.timestamp >= window_start
            )
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            elif client_ip:
                query = query.filter(AuditLog.ip_address == client_ip)

            recent_downloads = query.count()
            if recent_downloads >= 10:
                score += 50
                reasons.append(f"High download spike: {recent_downloads} downloads in under 2 minutes.")
            elif recent_downloads >= 5:
                score += 25
                reasons.append(f"Moderate download burst: {recent_downloads} downloads in under 2 minutes.")

        # Rule 2: IP / Device Anomaly (User logging in or accessing from an unfamiliar IP)
        if user_id and client_ip:
            known_ip = AuditLog.query.filter(
                AuditLog.user_id == user_id,
                AuditLog.ip_address == client_ip,
                AuditLog.action == AuditAction.LOGIN_SUCCESS
            ).first()
            if not known_ip:
                score += 20
                reasons.append(f"Unrecognized client IP address: {client_ip}.")

        # Rule 3: Prior failed login attempts for this user within 15 minutes
        if user_id:
            recent_failed = AuditLog.query.filter(
                AuditLog.user_id == user_id,
                AuditLog.action == AuditAction.LOGIN_FAILED,
                AuditLog.timestamp >= now - timedelta(minutes=15)
            ).count()
            if recent_failed >= 3:
                score += 25
                reasons.append(f"Multiple failed logins ({recent_failed}) preceded this session.")

        # Rule 4: High-Classification resource scrutiny
        if target_file and target_file.classification == Classification.HIGHLY_CONFIDENTIAL:
            score += 15
            reasons.append("Accessing HIGHLY_CONFIDENTIAL protected resource.")

        # Cap score at 100
        score = min(100, score)

        # Determine decision
        if score >= cls.RISK_THRESHOLD_BLOCK:
            decision = RiskDecision.BLOCK
        elif score >= cls.RISK_THRESHOLD_WARN:
            decision = RiskDecision.WARN
        else:
            decision = RiskDecision.ALLOW

        # Log anomaly if score >= threshold
        if score >= cls.RISK_THRESHOLD_WARN:
            AuditService.log(
                action=AuditAction.SUSPICIOUS_ACTIVITY_DETECTED,
                status=AuditStatus.BLOCKED if decision == RiskDecision.BLOCK else AuditStatus.WARNING,
                user=user,
                resource_type="File" if target_file else None,
                resource_id=target_file.id if target_file else None,
                details=f"Risk Score: {score}/100 | Decision: {decision} | Reasons: {'; '.join(reasons)}"
            )

        return score, decision, reasons
