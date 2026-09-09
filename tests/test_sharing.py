import pytest
from datetime import datetime, timezone, timedelta
from app.models.file import File, Classification
from app.models.share_link import ShareLink
from app.services.share_service import ShareService, SharePolicyViolationError
from app.services.encryption import EncryptionService
from app.config import Config
from app.extensions import db

from app.models.user import User

@pytest.fixture
def test_shared_file(app, standard_user):
    with app.app_context():
        user = db.session.get(User, standard_user.id)
        content = b"Shared document for team collaboration testing."
        envelope = EncryptionService.encrypt_file_envelope(content, Config.MASTER_ENCRYPTION_KEY)
        
        file_obj = File(
            original_name="team_doc.txt",
            mime_type="text/plain",
            file_size=len(content),
            sha256_hash=envelope["sha256_hash"],
            classification=Classification.INTERNAL,
            encrypted_key=envelope["encrypted_key"],
            key_nonce=envelope["key_nonce"],
            file_nonce=envelope["file_nonce"],
            owner_id=user.id
        )
        storage_path = Config.STORAGE_DIR / file_obj.storage_name
        with open(storage_path, "wb") as f:
            f.write(envelope["encrypted_blob"])

        db.session.add(file_obj)
        db.session.commit()
        db.session.refresh(file_obj)
        db.session.expunge(file_obj)
        return file_obj

def test_share_link_creation_and_download(client, test_shared_file, standard_user, app):
    """Verify share link generation and public download verification."""
    with app.app_context():
        file_obj = db.session.get(File, test_shared_file.id)
        user = db.session.get(User, standard_user.id)
        link = ShareService.create_share_link(
            file=file_obj,
            user=user,
            expiry_hours=24,
            max_downloads=0
        )
        token = link.token

    # Access share page
    resp = client.get(f"/s/{token}")
    assert resp.status_code == 200
    assert b"Encrypted File Available" in resp.data

    # Download file
    dl_resp = client.get(f"/s/{token}/download")
    assert dl_resp.status_code == 200
    assert dl_resp.headers.get("X-File-Integrity") == "VERIFIED"
    assert dl_resp.data == b"Shared document for team collaboration testing."

def test_expired_share_link_rejected(client, test_shared_file, standard_user, app):
    """Verify expired share link is rejected with appropriate security notice."""
    with app.app_context():
        file_obj = db.session.get(File, test_shared_file.id)
        user = db.session.get(User, standard_user.id)
        # Create already-expired link
        link = ShareLink(
            file_id=file_obj.id,
            token="expired_token_12345",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=2),
            created_by_id=user.id,
            is_active=True
        )
        db.session.add(link)
        db.session.commit()

    resp = client.get("/s/expired_token_12345")
    assert resp.status_code == 200
    assert b"This share link has expired" in resp.data

def test_one_time_burn_link_invalidated_after_download(client, test_shared_file, standard_user, app):
    """Verify one-time link invalidates immediately after first download ('LINK ALREADY USED')."""
    with app.app_context():
        file_obj = db.session.get(File, test_shared_file.id)
        user = db.session.get(User, standard_user.id)
        link = ShareService.create_share_link(
            file=file_obj,
            user=user,
            expiry_hours=12,
            is_one_time=True
        )
        token = link.token

    # 1st download succeeds
    first_dl = client.get(f"/s/{token}/download")
    assert first_dl.status_code == 200
    assert first_dl.data == b"Shared document for team collaboration testing."

    # 2nd download attempt must fail
    second_dl = client.get(f"/s/{token}/download")
    assert b"LINK ALREADY USED" in second_dl.data

def test_password_protected_share_link(client, test_shared_file, standard_user, app, get_csrf_token):
    """Verify password protected share link blocks unauthenticated downloads."""
    with app.app_context():
        file_obj = db.session.get(File, test_shared_file.id)
        user = db.session.get(User, standard_user.id)
        link = ShareService.create_share_link(
            file=file_obj,
            user=user,
            expiry_hours=24,
            password="VaultPassphrase2026!"
        )
        token = link.token

    # Initial visit requests password
    page_resp = client.get(f"/s/{token}")
    assert b"Password Protected Link" in page_resp.data

    csrf = get_csrf_token(page_resp.get_data(as_text=True))

    # Incorrect password attempt
    wrong_resp = client.post(f"/s/{token}", data={
        "csrf_token": csrf,
        "password": "WrongPassword!"
    }, follow_redirects=True)
    assert b"Incorrect password" in wrong_resp.data

    # Correct password unlocks
    correct_resp = client.post(f"/s/{token}", data={
        "csrf_token": csrf,
        "password": "VaultPassphrase2026!"
    }, follow_redirects=True)
    assert b"Password verified successfully" in correct_resp.data

def test_highly_confidential_policy_blocks_public_share_links(app, standard_user):
    """Zero-Trust Policy: HIGHLY_CONFIDENTIAL files cannot be shared via public links."""
    with app.app_context():
        user = db.session.get(User, standard_user.id)
        secret_file = File(
            original_name="classified_keys.pem",
            mime_type="text/plain",
            file_size=128,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            classification=Classification.HIGHLY_CONFIDENTIAL,
            encrypted_key="dummy_key",
            key_nonce="dummy_nonce",
            file_nonce="dummy_file_nonce",
            owner_id=user.id
        )
        db.session.add(secret_file)
        db.session.commit()

        # Attempting to create a share link must trigger SharePolicyViolationError
        with pytest.raises(SharePolicyViolationError) as exc_info:
            ShareService.create_share_link(
                file=secret_file,
                user=user,
                expiry_hours=24
            )

        assert "HIGHLY_CONFIDENTIAL" in str(exc_info.value)

