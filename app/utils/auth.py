from functools import wraps
from datetime import datetime, timezone
import secrets
from flask import session, redirect, url_for, flash, request, abort, g
from app.extensions import db
from app.models.user import User
from app.models.user_session import UserSession
from app.services.audit_service import AuditService
from app.models.audit_log import AuditAction, AuditStatus

def get_current_user():
    """Retrieve currently authenticated user from session and verify session is active."""
    user_id = session.get("user_id")
    if not user_id:
        return None

    # Check session tracking token if present
    session_token = session.get("session_token")
    if session_token:
        token_hash = UserSession.hash_token(session_token)
        user_sess = UserSession.query.filter_by(session_token_hash=token_hash).first()
        if user_sess:
            if user_sess.is_revoked:
                # Session has been revoked by user or admin
                session.clear()
                if hasattr(g, "current_user"):
                    g.current_user = None
                return None
            else:
                # Update last active timestamp
                user_sess.last_active_at = datetime.now(timezone.utc)
                db.session.commit()

    if not hasattr(g, "current_user") or g.current_user is None or g.current_user.id != user_id:
        g.current_user = db.session.get(User, user_id)
    return g.current_user

def establish_user_session(user: User) -> str:
    """Rotate and establish a tracked user session record upon successful authentication."""
    csrf_token_val = session.get("csrf_token")
    session.clear()
    if csrf_token_val:
        session["csrf_token"] = csrf_token_val
    session["user_id"] = user.id
    raw_token = secrets.token_hex(32)
    session["session_token"] = raw_token
    session.permanent = True

    # Capture device details
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()
    user_agent = request.headers.get("User-Agent", "")[:255]
    device_name = UserSession.parse_device_name(user_agent)

    new_session = UserSession(
        user_id=user.id,
        session_token_hash=UserSession.hash_token(raw_token),
        ip_address=client_ip,
        user_agent=user_agent,
        device_name=device_name
    )
    db.session.add(new_session)
    db.session.commit()
    return raw_token

def login_required(f):
    """Ensure user is logged in before accessing protected views."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or not user.is_active:
            flash("Authentication required. Please sign in to access this resource.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Strict RBAC: Ensure user has ADMIN role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or not user.is_active:
            flash("Authentication required.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        if not user.is_admin:
            AuditService.log(
                action=AuditAction.UNAUTHORIZED_ACCESS,
                status=AuditStatus.BLOCKED,
                user=user,
                details=f"Non-admin user '{user.username}' attempted to access admin endpoint: {request.path}"
            )
            abort(403)
        return f(*args, **kwargs)
    return decorated_function
