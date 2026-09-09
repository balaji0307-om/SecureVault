import io
import pytest
from app.models.file import File
from app.models.permission import FilePermission, PermissionType
from app.services.encryption import EncryptionService
from app.config import Config
from app.extensions import db

@pytest.fixture
def alice_file(app, standard_user):
    """Fixture creating an encrypted file owned by Alice."""
    with app.app_context():
        from app.models.user import User
        user = db.session.get(User, standard_user.id)
        content = b"Confidential financial audit for Alice's department."
        envelope = EncryptionService.encrypt_file_envelope(content, Config.MASTER_ENCRYPTION_KEY)
        
        file_obj = File(
            original_name="alice_ledger.csv",
            mime_type="text/csv",
            file_size=len(content),
            sha256_hash=envelope["sha256_hash"],
            classification="CONFIDENTIAL",
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
        return file_obj.id


def test_idor_non_owner_blocked_from_download(client, second_user, alice_file):
    """IDOR Check: Non-owner without permission receives 403 Forbidden."""
    with client.session_transaction() as sess:
        sess["user_id"] = second_user.id

    resp = client.get(f"/files/{alice_file}/download")
    assert resp.status_code == 403

def test_fine_grained_permission_grant_and_enforcement(client, standard_user, second_user, alice_file, app, get_csrf_token):
    """Verify fine-grained permission granting allows DOWNLOAD but blocks DELETE."""
    # Alice grants Bob DOWNLOAD permission
    with app.app_context():
        perm = FilePermission(
            file_id=alice_file,
            user_id=second_user.id,
            permission=PermissionType.DOWNLOAD,
            granted_by_id=standard_user.id
        )
        db.session.add(perm)
        db.session.commit()

    # Bob can now download
    with client.session_transaction() as sess:
        sess["user_id"] = second_user.id

    download_resp = client.get(f"/files/{alice_file}/download")
    assert download_resp.status_code == 200
    assert b"Confidential financial audit" in download_resp.data

    # Bob attempts DELETE without DELETE permission
    resp = client.get("/files")
    token = get_csrf_token(resp.get_data(as_text=True))
    delete_resp = client.post(f"/files/{alice_file}/delete", data={"csrf_token": token})
    assert delete_resp.status_code == 403

def test_admin_can_download_any_file(client, admin_user, alice_file):
    """Admin RBAC: Administrator accounts can manage and access all vault files."""
    with client.session_transaction() as sess:
        sess["user_id"] = admin_user.id

    admin_download = client.get(f"/files/{alice_file}/download")
    assert admin_download.status_code == 200
    assert b"Confidential financial audit" in admin_download.data

def test_regular_user_blocked_from_admin_center(client, standard_user):
    """RBAC check: Non-admin users cannot access administrative endpoints."""
    with client.session_transaction() as sess:
        sess["user_id"] = standard_user.id

    for endpoint in ["/admin", "/admin/users", "/security/audit", "/security/risk"]:
        resp = client.get(endpoint)
        assert resp.status_code == 403

def test_highly_confidential_download_requires_step_up_reauth(client, standard_user, app, get_csrf_token):
    """Verify downloading HIGHLY_CONFIDENTIAL file redirects to step-up reauth challenge."""
    from app.models.file import File, Classification
    from app.services.encryption import EncryptionService
    from app.config import Config

    with app.app_context():
        content = b"TOP SECRET BOARD MINUTES"
        envelope = EncryptionService.encrypt_file_envelope(content, Config.MASTER_ENCRYPTION_KEY)
        hc_file = File(
            original_name="board_minutes.txt",
            mime_type="text/plain",
            file_size=len(content),
            sha256_hash=envelope["sha256_hash"],
            classification=Classification.HIGHLY_CONFIDENTIAL,
            encrypted_key=envelope["encrypted_key"],
            key_nonce=envelope["key_nonce"],
            file_nonce=envelope["file_nonce"],
            owner_id=standard_user.id
        )
        storage_path = Config.STORAGE_DIR / hc_file.storage_name
        with open(storage_path, "wb") as out:
            out.write(envelope["encrypted_blob"])
        db.session.add(hc_file)
        db.session.commit()
        hc_file_id = hc_file.id

    with client.session_transaction() as sess:
        sess["user_id"] = standard_user.id

    # First download attempt should redirect to reauth page
    initial_resp = client.get(f"/files/{hc_file_id}/download")
    assert initial_resp.status_code == 302
    assert f"/files/{hc_file_id}/reauth" in initial_resp.headers["Location"]

    # Access reauth page
    reauth_page = client.get(f"/files/{hc_file_id}/reauth")
    assert reauth_page.status_code == 200
    assert b"Step-Up Re-Authentication" in reauth_page.data

    # Submit correct password to clear step-up authorization
    token = get_csrf_token(reauth_page.get_data(as_text=True))
    post_reauth = client.post(f"/files/{hc_file_id}/reauth", data={
        "csrf_token": token,
        "password": "AlicePass123!"
    })
    assert post_reauth.status_code == 302
    assert f"/files/{hc_file_id}/download" in post_reauth.headers["Location"]

    # Now download succeeds with cleared session
    cleared_download = client.get(f"/files/{hc_file_id}/download")
    assert cleared_download.status_code == 200
    assert cleared_download.data == b"TOP SECRET BOARD MINUTES"

