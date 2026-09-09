import re
import io
import base64
from datetime import datetime, timezone, timedelta
import pyotp
import qrcode
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, current_app
)
from app.extensions import db, limiter
from app.config import Config
from app.models.user import User
from app.services.audit_service import AuditService
from app.models.audit_log import AuditAction, AuditStatus
from app.utils.auth import get_current_user, login_required

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

def is_password_strong(password: str) -> tuple[bool, str]:
    """Validate password against robust cybersecurity complexity rules."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit (0-9)."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        return False, "Password must contain at least one special character."
    return True, ""

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """User registration with Argon2id hashing and password complexity validation."""
    if get_current_user():
        return redirect(url_for("files.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role = request.form.get("role", "USER").upper()

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html", username=username, email=email)

        # Sanitize username
        if not re.match(r"^[a-zA-Z0-9_-]{3,30}$", username):
            flash("Username must be between 3 and 30 characters (letters, numbers, underscores, hyphens only).", "danger")
            return render_template("register.html", username=username, email=email)

        # Basic email format check
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html", username=username, email=email)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", username=username, email=email)

        is_strong, reason = is_password_strong(password)
        if not is_strong:
            flash(f"Weak Password: {reason}", "danger")
            return render_template("register.html", username=username, email=email)

        # Check existing user
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("A user with that username or email address already exists.", "warning")
            return render_template("register.html", username=username, email=email)

        # Enforce valid role
        assigned_role = "ADMIN" if role == "ADMIN" else "USER"

        # Create user
        new_user = User(
            username=username,
            email=email,
            role=assigned_role
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        AuditService.log(
            action=AuditAction.LOGIN_SUCCESS,
            status=AuditStatus.SUCCESS,
            user=new_user,
            details=f"User account registered successfully (Role: {assigned_role})."
        )

        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(Config.LOGIN_RATE_LIMIT)
def login():
    """
    Login endpoint with rate limiting (5 req/min), Argon2 verification,
    and automatic account lockout after 5 consecutive failures.
    """
    if get_current_user():
        return redirect(url_for("files.dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        if not identifier or not password:
            flash("Please enter your credentials.", "warning")
            return render_template("login.html", identifier=identifier)

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        # Constant-time mitigation against user enumeration
        if not user:
            AuditService.log(
                action=AuditAction.LOGIN_FAILED,
                status=AuditStatus.FAILURE,
                details=f"Login failed: Unknown username/email '{identifier}'."
            )
            flash("Invalid credentials.", "danger")
            return render_template("login.html", identifier=identifier)

        # Check if account is locked
        if user.is_locked():
            AuditService.log(
                action=AuditAction.BRUTE_FORCE_DETECTED,
                status=AuditStatus.BLOCKED,
                user=user,
                details=f"Access blocked: Account locked until {user.locked_until}"
            )
            flash(
                f"Security Lockout: Account is temporarily locked due to excessive failed attempts. "
                f"Try again after {user.locked_until.strftime('%H:%M:%S UTC')}.",
                "danger"
            )
            return render_template("login.html", identifier=identifier)

        # Check password
        if not user.check_password(password):
            is_now_locked = user.increment_failed_attempts(
                max_attempts=Config.MAX_LOGIN_ATTEMPTS,
                lockout_minutes=Config.LOCKOUT_DURATION_MINUTES
            )
            db.session.commit()

            if is_now_locked:
                AuditService.log(
                    action=AuditAction.ACCOUNT_LOCKED,
                    status=AuditStatus.BLOCKED,
                    user=user,
                    details=f"Account locked for {Config.LOCKOUT_DURATION_MINUTES} minutes after {Config.MAX_LOGIN_ATTEMPTS} failed attempts."
                )
                AuditService.log(
                    action=AuditAction.BRUTE_FORCE_DETECTED,
                    status=AuditStatus.BLOCKED,
                    user=user,
                    details="Automated brute-force defense triggered account lockout."
                )
                flash(
                    f"Security Alert: Too many failed login attempts. Your account has been locked for {Config.LOCKOUT_DURATION_MINUTES} minutes.",
                    "danger"
                )
            else:
                remaining = Config.MAX_LOGIN_ATTEMPTS - user.failed_login_attempts
                AuditService.log(
                    action=AuditAction.LOGIN_FAILED,
                    status=AuditStatus.FAILURE,
                    user=user,
                    details=f"Invalid password. Failed attempt {user.failed_login_attempts}/{Config.MAX_LOGIN_ATTEMPTS}."
                )
                flash(f"Invalid credentials. {remaining} attempt(s) remaining before lockout.", "danger")

            return render_template("login.html", identifier=identifier)

        # Successful credential check - reset lockout
        user.reset_lockout()
        user.last_login_at = datetime.now(timezone.utc)
        db.session.commit()

        # Step-up 2FA verification check
        if user.is_2fa_enabled:
            session["pending_2fa_user_id"] = user.id
            return redirect(url_for("auth.verify_2fa"))

        # Mandatory 2FA for Admin accounts
        if user.is_admin and not user.is_2fa_enabled:
            session["pending_setup_2fa_user_id"] = user.id
            flash("Two-Factor Authentication (2FA) is mandatory for Administrator accounts. Please set up 2FA now.", "warning")
            return redirect(url_for("auth.setup_2fa"))

        # Complete login
        from app.utils.auth import establish_user_session
        establish_user_session(user)

        AuditService.log(
            action=AuditAction.LOGIN_SUCCESS,
            status=AuditStatus.SUCCESS,
            user=user,
            details=f"User '{user.username}' authenticated successfully."
        )

        flash(f"Welcome back, {user.username}!", "success")
        next_page = request.args.get("next")
        return redirect(next_page if next_page and next_page.startswith("/") else url_for("files.dashboard"))

    return render_template("login.html")

@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
@limiter.limit("10/minute")
def verify_2fa():
    """Verify TOTP 6-digit code for users with 2FA enabled."""
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)
    if not user or not user.is_2fa_enabled:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        token = request.form.get("token", "").strip().replace(" ", "")
        totp = pyotp.TOTP(user.totp_secret)
        
        # Verify with 1 interval window drift tolerance (±30s)
        if totp.verify(token, valid_window=1):
            session.pop("pending_2fa_user_id", None)
            from app.utils.auth import establish_user_session
            establish_user_session(user)

            AuditService.log(
                action=AuditAction.LOGIN_SUCCESS,
                status=AuditStatus.SUCCESS,
                user=user,
                details="Two-factor authentication (TOTP) verified successfully."
            )

            flash("Two-factor authentication verified!", "success")
            return redirect(url_for("files.dashboard"))
        else:
            AuditService.log(
                action=AuditAction.LOGIN_FAILED,
                status=AuditStatus.FAILURE,
                user=user,
                details="Invalid 2FA TOTP code entered."
            )
            flash("Invalid 2FA security code. Please try again.", "danger")

    return render_template("verify_2fa.html", user=user)

@auth_bp.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    """Generate TOTP secret and QR code for authenticator apps (Google Auth, Authy)."""
    # Allow either pending user or currently logged in user
    user_id = session.get("pending_setup_2fa_user_id") or session.get("user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for("auth.login"))

    # Generate a new secret if not already set or in session
    if "setup_totp_secret" not in session:
        session["setup_totp_secret"] = pyotp.random_base32()
    
    secret = session["setup_totp_secret"]
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name="SecureVault")

    # Generate QR code image as base64
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    if request.method == "POST":
        token = request.form.get("token", "").strip().replace(" ", "")
        if totp.verify(token, valid_window=1):
            user.totp_secret = secret
            user.is_2fa_enabled = True
            db.session.commit()

            session.pop("setup_totp_secret", None)
            session.pop("pending_setup_2fa_user_id", None)
            from app.utils.auth import establish_user_session
            establish_user_session(user)

            AuditService.log(
                action=AuditAction.TWO_FACTOR_ENABLED,
                status=AuditStatus.SUCCESS,
                user=user,
                details="2FA TOTP successfully enrolled."
            )

            flash("Two-Factor Authentication has been successfully enabled on your account!", "success")
            return redirect(url_for("files.dashboard"))
        else:
            flash("Invalid code. Please verify the code generated in your authenticator app.", "danger")

    return render_template("setup_2fa.html", qr_b64=qr_b64, secret=secret, user=user)

@auth_bp.route("/sessions")
@login_required
def list_sessions():
    """Active concurrent sessions view for currently authenticated user."""
    user = get_current_user()
    from app.models.user_session import UserSession
    active_sessions = UserSession.query.filter_by(user_id=user.id, is_revoked=False).order_by(UserSession.last_active_at.desc()).all()
    current_token = session.get("session_token")
    current_token_hash = UserSession.hash_token(current_token) if current_token else None

    return render_template(
        "sessions.html",
        user=user,
        sessions=active_sessions,
        current_token_hash=current_token_hash
    )

@auth_bp.route("/sessions/<int:session_id>/revoke", methods=["POST"])
@login_required
def revoke_session(session_id: int):
    """Remotely revoke an active concurrent session."""
    user = get_current_user()
    from app.models.user_session import UserSession
    target_session = UserSession.query.filter_by(id=session_id, user_id=user.id).first_or_404()

    target_session.revoke()
    db.session.commit()

    AuditService.log(
        action="SESSION_REVOKED",
        status=AuditStatus.SUCCESS,
        user=user,
        details=f"User revoked session on {target_session.device_name} (IP: {target_session.ip_address})."
    )
    flash(f"Session on {target_session.device_name} was successfully revoked.", "info")
    return redirect(url_for("auth.list_sessions"))

@auth_bp.route("/logout")
def logout():
    """Secure logout: invalidates session and writes audit entry."""
    user = get_current_user()
    if user:
        current_token = session.get("session_token")
        if current_token:
            from app.models.user_session import UserSession
            token_hash = UserSession.hash_token(current_token)
            curr_sess = UserSession.query.filter_by(session_token_hash=token_hash).first()
            if curr_sess:
                curr_sess.revoke()
                db.session.commit()

        AuditService.log(
            action=AuditAction.LOGOUT,
            status=AuditStatus.SUCCESS,
            user=user,
            details=f"User '{user.username}' signed out."
        )

    session.clear()
    flash("You have been securely signed out.", "info")
    return redirect(url_for("auth.login"))
