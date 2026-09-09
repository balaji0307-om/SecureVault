import io
import pytest
from pathlib import Path
from app.models.file import File, Classification
from app.config import Config
from app.extensions import db


def test_upload_valid_file_envelope_encrypted(client, standard_user, get_csrf_token, app):
    """Verify file upload executes AES-256-GCM envelope encryption and stores under UUID."""
    # Simulate user session
    with client.session_transaction() as sess:
        sess["user_id"] = standard_user.id

    resp = client.get("/files")
    token = get_csrf_token(resp.get_data(as_text=True))

    file_content = b"TOP SECRET MISSION PLAN: Cybersecurity Internship Demonstration Payload."
    upload_resp = client.post("/files/upload", data={
        "csrf_token": token,
        "file": (io.BytesIO(file_content), "secret_report.txt"),
        "classification": "CONFIDENTIAL"
    }, follow_redirects=True)

    assert b"successfully encrypted" in upload_resp.data

    with app.app_context():
        file_record = File.query.filter_by(original_name="secret_report.txt").first()
        assert file_record is not None
        assert file_record.owner_id == standard_user.id
        assert file_record.classification == Classification.CONFIDENTIAL

        # Verify disk file is ciphertext, NOT plaintext
        disk_path = Config.STORAGE_DIR / file_record.storage_name
        assert disk_path.exists()

        with open(disk_path, "rb") as f:
            disk_bytes = f.read()

        # Plaintext must NOT appear in the encrypted blob
        assert b"TOP SECRET MISSION PLAN" not in disk_bytes
        assert len(disk_bytes) > 0

@pytest.fixture
def uploaded_file(app, standard_user):
    """Fixture creating an encrypted file owned by standard_user."""
    with app.app_context():
        from app.models.user import User
        from app.services.encryption import EncryptionService
        user = db.session.get(User, standard_user.id)
        content = b"TOP SECRET MISSION PLAN: Cybersecurity Internship Demonstration Payload."
        envelope = EncryptionService.encrypt_file_envelope(content, Config.MASTER_ENCRYPTION_KEY)
        f = File(
            original_name="secret_report.txt",
            mime_type="text/plain",
            file_size=len(content),
            sha256_hash=envelope["sha256_hash"],
            classification=Classification.CONFIDENTIAL,
            encrypted_key=envelope["encrypted_key"],
            key_nonce=envelope["key_nonce"],
            file_nonce=envelope["file_nonce"],
            owner_id=user.id
        )
        storage_path = Config.STORAGE_DIR / f.storage_name
        with open(storage_path, "wb") as out:
            out.write(envelope["encrypted_blob"])
        db.session.add(f)
        db.session.commit()
        return f.id

def test_download_and_integrity_verification(client, standard_user, uploaded_file):
    """Verify file download decrypts payload and confirms SHA-256 integrity."""
    with client.session_transaction() as sess:
        sess["user_id"] = standard_user.id

    download_resp = client.get(f"/files/{uploaded_file}/download")
    assert download_resp.status_code == 200
    assert download_resp.headers.get("X-File-Integrity") == "VERIFIED"
    assert download_resp.data == b"TOP SECRET MISSION PLAN: Cybersecurity Internship Demonstration Payload."

def test_disallowed_extension_rejection(client, standard_user, get_csrf_token):
    """Verify dangerous executable extensions (.exe, .sh, .py) are rejected."""
    with client.session_transaction() as sess:
        sess["user_id"] = standard_user.id

    resp = client.get("/files")
    token = get_csrf_token(resp.get_data(as_text=True))

    malicious_upload = client.post("/files/upload", data={
        "csrf_token": token,
        "file": (io.BytesIO(b"MZ\x90\x00\x03\x00\x00\x00"), "payload.exe"),
        "classification": "INTERNAL"
    }, follow_redirects=True)

    assert b"Execution security violation" in malicious_upload.data

def test_renamed_executable_spoofing_rejected(client, standard_user, get_csrf_token):
    """Verify content-based magic byte check rejects executable disguised as safe PDF."""
    with client.session_transaction() as sess:
        sess["user_id"] = standard_user.id

    resp = client.get("/files")
    token = get_csrf_token(resp.get_data(as_text=True))

    # PE Header (MZ) pretending to be report.pdf
    spoofed_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    upload_resp = client.post("/files/upload", data={
        "csrf_token": token,
        "file": (io.BytesIO(spoofed_payload), "annual_report.pdf"),
        "classification": "INTERNAL"
    }, follow_redirects=True)

    assert b"signature mismatch" in upload_resp.data or b"executable binary header detected" in upload_resp.data

def test_eicar_malware_detection_and_quarantine(client, standard_user, get_csrf_token, app):
    """Verify upload of EICAR test string is detected, quarantined, and audited as CRITICAL."""
    with client.session_transaction() as sess:
        sess["user_id"] = standard_user.id

    resp = client.get("/files")
    token = get_csrf_token(resp.get_data(as_text=True))

    eicar_string = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    upload_resp = client.post("/files/upload", data={
        "csrf_token": token,
        "file": (io.BytesIO(eicar_string), "sample_eicar.txt"),
        "classification": "INTERNAL"
    }, follow_redirects=True)

    assert b"Malware detected" in upload_resp.data
    assert b"isolated in quarantine" in upload_resp.data

    with app.app_context():
        from app.models.audit_log import AuditLog, AuditAction, AuditSeverity
        # Verify quarantine directory has at least one .quarantine file
        quarantined_files = list(Config.QUARANTINE_DIR.glob("*.quarantine"))
        assert len(quarantined_files) > 0

        # Verify audit log entry with CRITICAL severity
        malware_log = AuditLog.query.filter_by(action=AuditAction.MALWARE_DETECTED).first()
        assert malware_log is not None
        assert malware_log.severity == AuditSeverity.CRITICAL

def test_tampered_blob_integrity_failure(client, standard_user, uploaded_file, app):
    """Verify that tampering with an encrypted blob causes integrity rejection."""
    with client.session_transaction() as sess:
        sess["user_id"] = standard_user.id

    with app.app_context():
        file_record = db.session.get(File, uploaded_file)
        disk_path = Config.STORAGE_DIR / file_record.storage_name

        # Tamper with the raw ciphertext on disk
        with open(disk_path, "r+b") as f:
            data = f.read()
            # Flip byte
            tampered = bytearray(data)
            tampered[5] = tampered[5] ^ 0xFF
            f.seek(0)
            f.write(tampered)

    # Attempt download of corrupted/tampered blob
    resp = client.get(f"/files/{uploaded_file}/download", follow_redirects=True)
    # GCM tag mismatch or SHA-256 failure will be raised
    assert b"Decryption failed" in resp.data or b"integrity check failed" in resp.data

def test_secure_shredding_deletion(client, standard_user, uploaded_file, get_csrf_token, app):
    """Verify secure deletion overwrites and shreds disk blob and database entry."""
    with client.session_transaction() as sess:
        sess["user_id"] = standard_user.id

    with app.app_context():
        file_record = db.session.get(File, uploaded_file)
        disk_path = Config.STORAGE_DIR / file_record.storage_name

    resp = client.get("/files")
    token = get_csrf_token(resp.get_data(as_text=True))

    delete_resp = client.post(f"/files/{uploaded_file}/delete", data={
        "csrf_token": token
    }, follow_redirects=True)

    assert b"3-pass overwrite-based secure deletion" in delete_resp.data

    # Verify disk blob is gone
    assert not disk_path.exists()

    # Verify DB record is gone
    with app.app_context():
        assert db.session.get(File, uploaded_file) is None


