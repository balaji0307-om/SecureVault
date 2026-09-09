import os
import re
import pytest
from pathlib import Path
from app import create_app
from app.config import Config
from app.extensions import db as _db
from app.models.user import User

class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = True  # Keep CSRF active to test security
    SECRET_KEY = "test-secret-key-for-pytest-execution-992288"
    MASTER_ENCRYPTION_KEY = b"SECUREVAULT_32_BYTE_DEV_KEY_001!"
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15
    LOGIN_RATE_LIMIT = "5/minute"
    RATELIMIT_ENABLED = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_SESSION_OPTIONS = {"expire_on_commit": False}

@pytest.fixture
def app(tmp_path):
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir(parents=True, exist_ok=True)
    db_file = tmp_path / "test.db"
    
    TestConfig.STORAGE_DIR = storage_dir
    TestConfig.SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_file}"
    TestConfig.MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB for testing

    app = create_app(TestConfig)

    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def db(app):
    return _db

def extract_csrf_token(html: str) -> str:
    """Extract CSRF token value from HTML response."""
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if not match:
        match = re.search(r'name="csrf-token"\s+content="([^"]+)"', html)
    if not match:
        match = re.search(r'content="([^"]+)"\s+name="csrf-token"', html)
    return match.group(1) if match else ""


@pytest.fixture
def get_csrf_token():
    return extract_csrf_token

@pytest.fixture
def admin_user(app):
    with app.app_context():
        admin = User(
            username="admin_test",
            email="admin@test.local",
            role="ADMIN",
            is_active=True
        )
        admin.set_password("AdminPass123!")
        _db.session.add(admin)
        _db.session.commit()
        _db.session.refresh(admin)
        _db.session.expunge(admin)
        return admin

@pytest.fixture
def standard_user(app):
    with app.app_context():
        user = User(
            username="alice_test",
            email="alice@test.local",
            role="USER",
            is_active=True
        )
        user.set_password("AlicePass123!")
        _db.session.add(user)
        _db.session.commit()
        _db.session.refresh(user)
        _db.session.expunge(user)
        return user

@pytest.fixture
def second_user(app):
    with app.app_context():
        user = User(
            username="bob_test",
            email="bob@test.local",
            role="USER",
            is_active=True
        )
        user.set_password("BobPass123!@#")
        _db.session.add(user)
        _db.session.commit()
        _db.session.refresh(user)
        _db.session.expunge(user)
        return user

