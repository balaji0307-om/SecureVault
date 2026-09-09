import pytest
from app.services.file_validator import FileValidator, FileValidationError
from app.services.risk_engine import RiskEngine, RiskDecision
from app.models.audit_log import AuditLog, AuditAction
from app.extensions import db

def test_csrf_protection_enforced(client):
    """Verify state-changing POST requests without CSRF token are rejected with HTTP 400."""
    # Attempting to register without CSRF token
    resp = client.post("/auth/register", data={
        "username": "attacker",
        "email": "attacker@evil.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })
    assert resp.status_code == 400

def test_path_traversal_prevention():
    """Verify path traversal sequences ('../', '..\\', null bytes) are blocked by validator."""
    traversal_filenames = [
        "../../etc/passwd",
        "..\\..\\Windows\\System32\\cmd.exe",
        "nested/../../secret.txt",
        "test.txt\x00.exe",
        "../../../boot.ini"
    ]

    for malicious_name in traversal_filenames:
        with pytest.raises(FileValidationError) as exc:
            FileValidator.sanitize_filename(malicious_name)
        assert "Path traversal" in str(exc.value)

def test_path_traversal_upload_rejected(client, standard_user, get_csrf_token):
    """Verify posting a path traversal payload ('../../etc/passwd') to upload route is rejected."""
    import io
    with client.session_transaction() as sess:
        sess["user_id"] = standard_user.id

    resp = client.get("/files")
    token = get_csrf_token(resp.get_data(as_text=True))

    malicious_upload = client.post("/files/upload", data={
        "csrf_token": token,
        "file": (io.BytesIO(b"root:x:0:0:root:/root:/bin/bash"), "../../etc/passwd"),
        "classification": "INTERNAL"
    }, follow_redirects=True)

    assert b"Path traversal sequence detected" in malicious_upload.data or b"Upload Rejected" in malicious_upload.data

def test_security_headers_enforced_on_responses(client):
    """Verify critical HTTP security headers are present on all outgoing responses."""
    resp = client.get("/auth/login")
    assert resp.status_code == 200

    headers = resp.headers
    # Content-Security-Policy
    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]

    # Clickjacking protection
    assert headers.get("X-Frame-Options") == "DENY"

    # MIME sniffing protection
    assert headers.get("X-Content-Type-Options") == "nosniff"

    # Referrer policy
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

def test_risk_engine_anomaly_detection(app, standard_user):
    """Verify rule-based risk engine flags rapid download velocity spikes."""
    with app.app_context():
        from app.models.user import User
        user = db.session.get(User, standard_user.id)
        # Simulate 12 rapid downloads in audit log
        for _ in range(12):
            log = AuditLog(
                user_id=user.id,
                username=user.username,
                action=AuditAction.FILE_DOWNLOADED,
                status="SUCCESS"
            )
            db.session.add(log)
        db.session.commit()

        # Evaluate risk score
        score, decision, reasons = RiskEngine.evaluate_request(
            user=user,
            action="DOWNLOAD"
        )

        assert score >= 50
        assert any("High download spike" in r for r in reasons)

def test_audit_severity_classification(app):
    """Verify security audit logs correctly derive severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)."""
    with app.app_context():
        from app.models.audit_log import AuditLog, AuditAction, AuditStatus, AuditSeverity
        from app.services.audit_service import AuditService

        # 1. Critical event
        log_crit = AuditService.log(
            action=AuditAction.BRUTE_FORCE_DETECTED,
            status=AuditStatus.BLOCKED,
            details="Brute force detected test"
        )
        assert log_crit.severity == AuditSeverity.CRITICAL

        # 2. High severity event
        log_high = AuditService.log(
            action=AuditAction.UNAUTHORIZED_ACCESS,
            status=AuditStatus.BLOCKED,
            details="Unauthorized access test"
        )
        assert log_high.severity == AuditSeverity.HIGH

        # 3. Medium severity event
        log_med = AuditService.log(
            action=AuditAction.SHARE_LINK_CREATED,
            status=AuditStatus.SUCCESS,
            details="Share link created test"
        )
        assert log_med.severity == AuditSeverity.MEDIUM

        # 4. Low severity event
        log_low = AuditService.log(
            action=AuditAction.FILE_UPLOADED,
            status=AuditStatus.SUCCESS,
            details="File uploaded test"
        )
        assert log_low.severity == AuditSeverity.LOW

        # 5. Info severity event
        log_info = AuditService.log(
            action=AuditAction.LOGIN_SUCCESS,
            status=AuditStatus.SUCCESS,
            details="Login success test"
        )
        assert log_info.severity == AuditSeverity.INFO


