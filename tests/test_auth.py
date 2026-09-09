import pytest
from app.models.user import User
from app.extensions import db

def test_argon2_password_hashing(app):
    """Verify password hashing meets Argon2id cryptographic requirements."""
    with app.app_context():
        user = User(username="cryptotest", email="crypto@test.local")
        user.set_password("CorrectHorseBatteryStaple123!")

        # Password hash must start with Argon2id identifier
        assert user.password_hash.startswith("$argon2id$")
        assert "CorrectHorseBatteryStaple123!" not in user.password_hash

        # Verification tests
        assert user.check_password("CorrectHorseBatteryStaple123!") is True
        assert user.check_password("WrongPassword123!") is False
        assert user.check_password("") is False

def test_user_registration(client, get_csrf_token):
    """Test user registration flow and password complexity validation."""
    resp = client.get("/auth/register")
    assert resp.status_code == 200
    token = get_csrf_token(resp.get_data(as_text=True))

    # Test 1: Weak password rejected
    resp_weak = client.post("/auth/register", data={
        "csrf_token": token,
        "username": "newuser",
        "email": "newuser@test.local",
        "password": "simplepassword",
        "confirm_password": "simplepassword",
        "role": "USER"
    }, follow_redirects=True)
    assert b"Weak Password" in resp_weak.data

    # Test 2: Robust registration
    resp_valid = client.post("/auth/register", data={
        "csrf_token": token,
        "username": "validaudituser",
        "email": "valid@test.local",
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
        "role": "USER"
    }, follow_redirects=True)
    assert b"Registration successful" in resp_valid.data

def test_login_success_and_logout(client, standard_user, get_csrf_token):
    """Test successful credential verification and session management."""
    resp = client.get("/auth/login")
    token = get_csrf_token(resp.get_data(as_text=True))

    # Log in
    login_resp = client.post("/auth/login", data={
        "csrf_token": token,
        "identifier": "alice_test",
        "password": "AlicePass123!"
    }, follow_redirects=False)

    assert login_resp.status_code == 302
    assert "/dashboard" in login_resp.headers["Location"]

    with client.session_transaction() as sess:
        assert sess.get("user_id") == standard_user.id

    # Test logout
    logout_resp = client.get("/auth/logout", follow_redirects=True)
    assert b"securely signed out" in logout_resp.data

    with client.session_transaction() as sess:
        assert "user_id" not in sess

def test_account_lockout_after_five_failed_attempts(client, standard_user, get_csrf_token, app):
    """Brute force mitigation: Verify account lock after 5 consecutive failures across IPs."""
    for attempt in range(1, 6):
        resp = client.get("/auth/login", environ_overrides={"REMOTE_ADDR": f"10.0.0.{attempt}"})
        token = get_csrf_token(resp.get_data(as_text=True))

        post_resp = client.post("/auth/login", data={
            "csrf_token": token,
            "identifier": "alice_test",
            "password": "IncorrectPassword999!"
        }, environ_overrides={"REMOTE_ADDR": f"10.0.0.{attempt}"}, follow_redirects=True)

        if attempt < 5:
            assert b"remaining before lockout" in post_resp.data
        else:
            assert b"Security Alert: Too many failed login attempts" in post_resp.data

    # Verify user state in DB
    with app.app_context():
        user = User.query.filter_by(username="alice_test").first()
        assert user.failed_login_attempts >= 5
        assert user.is_locked() is True

    # 6th attempt is blocked immediately by lockout
    resp = client.get("/auth/login", environ_overrides={"REMOTE_ADDR": "10.0.0.99"})
    token = get_csrf_token(resp.get_data(as_text=True))
    blocked_resp = client.post("/auth/login", data={
        "csrf_token": token,
        "identifier": "alice_test",
        "password": "AlicePass123!"  # Even with correct password, blocked until lockout expires
    }, environ_overrides={"REMOTE_ADDR": "10.0.0.99"}, follow_redirects=True)

    assert b"Security Lockout: Account is temporarily locked" in blocked_resp.data

def test_rate_limiting_triggers_429(client, get_csrf_token):
    """Verify rate limiter blocks high-frequency requests from the same IP with HTTP 429."""
    # Send 6 rapid requests from the exact same client IP
    hit_429 = False
    for i in range(7):
        resp = client.get("/auth/login", environ_overrides={"REMOTE_ADDR": "192.168.100.50"})
        token = get_csrf_token(resp.get_data(as_text=True))
        post_resp = client.post("/auth/login", data={
            "csrf_token": token,
            "identifier": "attacker",
            "password": "wrong"
        }, environ_overrides={"REMOTE_ADDR": "192.168.100.50"})

        if post_resp.status_code == 429 or b"Rate Limit Exceeded" in post_resp.data:
            hit_429 = True
            break

    assert hit_429 is True

def test_concurrent_session_tracking_and_revocation(client, standard_user, get_csrf_token, app):
    """Verify multiple device sessions can be created, viewed, and remotely revoked."""
    # 1. Login primary session (Desktop client)
    resp = client.get("/auth/login")
    token = get_csrf_token(resp.get_data(as_text=True))
    login_resp = client.post("/auth/login", data={
        "csrf_token": token,
        "identifier": "alice_test",
        "password": "AlicePass123!"
    }, environ_overrides={"HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0", "REMOTE_ADDR": "192.168.1.10"}, follow_redirects=True)
    assert login_resp.status_code == 200

    # 2. Simulate second active device session enrolled for the user (Mobile / Laptop)
    with app.app_context():
        from app.models.user_session import UserSession
        remote_raw_token = "mock_remote_device_token_xyz987654321"
        remote_sess = UserSession(
            user_id=standard_user.id,
            session_token_hash=UserSession.hash_token(remote_raw_token),
            ip_address="192.168.1.88",
            user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
            device_name="Safari on iPhone"
        )
        db.session.add(remote_sess)
        db.session.commit()
        remote_sess_id = remote_sess.id

    # 3. View sessions page from primary session
    sess_view = client.get("/auth/sessions")
    assert sess_view.status_code == 200
    assert b"Enrolled Sessions" in sess_view.data
    assert b"Safari on iPhone" in sess_view.data
    assert b"192.168.1.88" in sess_view.data

    # 4. Remotely revoke the secondary mobile session
    rev_token = get_csrf_token(sess_view.get_data(as_text=True))
    revoke_resp = client.post(f"/auth/sessions/{remote_sess_id}/revoke", data={
        "csrf_token": rev_token
    }, follow_redirects=True)
    assert revoke_resp.status_code == 200
    assert b"successfully revoked" in revoke_resp.data

    # 5. Verify in DB that the remote session is revoked while primary session remains active
    with app.app_context():
        from app.models.user_session import UserSession
        revoked_sess = db.session.get(UserSession, remote_sess_id)
        assert revoked_sess.is_revoked is True

        active_sessions = UserSession.query.filter_by(user_id=standard_user.id, is_revoked=False).all()
        assert len(active_sessions) >= 1
        assert all(s.id != remote_sess_id for s in active_sessions)

    # 6. Verify that a client presenting the revoked session token is instantly rejected
    with app.app_context():
        from app.utils.auth import get_current_user
        from flask import session as flask_session
        with app.test_request_context():
            flask_session["user_id"] = standard_user.id
            flask_session["session_token"] = remote_raw_token
            # Calling get_current_user detects the revoked session and clears it
            user_check = get_current_user()
            assert user_check is None
            assert "user_id" not in flask_session


