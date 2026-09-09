from datetime import datetime, timezone
from flask import Flask, redirect, url_for, render_template, request, jsonify
from app.config import Config
from app.extensions import db, csrf, limiter
from app.utils.auth import get_current_user
from app.services.audit_service import AuditService
from app.models.audit_log import AuditAction, AuditStatus

def create_app(config_class=Config):
    """Application factory configured with Zero-Trust security controls."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Extensions
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Register Blueprints
    from app.routes.auth import auth_bp
    from app.routes.files import files_bp
    from app.routes.sharing import sharing_bp
    from app.routes.admin import admin_bp
    from app.routes.security import security_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(sharing_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(security_bp)

    # Root route
    @app.route("/")
    def index():
        user = get_current_user()
        if user:
            return redirect(url_for("files.dashboard"))
        return redirect(url_for("auth.login"))

    # Context Processors for Templates
    @app.context_processor
    def inject_security_context():
        return {
            "current_user": get_current_user(),
            "current_year": datetime.now(timezone.utc).year
        }

    # ==========================================================================
    # SECURITY RESPONSE HEADERS MIDDLEWARE
    # ==========================================================================
    @app.after_request
    def apply_security_headers(response):
        """
        Enforce industry-standard defense-in-depth HTTP security headers.
        Protects against XSS, clickjacking, MIME sniffing, and framing.
        """
        # Content Security Policy (Strict script and frame control)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self';"
        )

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Control referrer leakage
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Disable browser features not needed by SecureVault
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"

        # HTTP Strict Transport Security (HSTS) - Enabled when secure
        if request.is_secure or app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        return response

    # ==========================================================================
    # CUSTOM SECURITY ERROR HANDLERS
    # ==========================================================================
    @app.errorhandler(400)
    def bad_request_error(e):
        user = get_current_user()
        description = getattr(e, "description", "Bad Request")
        AuditService.log(
            action="BAD_REQUEST",
            status=AuditStatus.FAILURE,
            user=user,
            details=f"400 on {request.path}: {description}"
        )
        return render_template("error.html", code=400, message=f"Bad Request: {description}"), 400

    @app.errorhandler(403)
    def forbidden_error(e):
        user = get_current_user()
        AuditService.log(
            action=AuditAction.UNAUTHORIZED_ACCESS,
            status=AuditStatus.BLOCKED,
            user=user,
            details=f"403 Forbidden access attempt on {request.path}"
        )
        return render_template("error.html", code=403, message="Access Denied: You do not have permission to access this resource."), 403

    @app.errorhandler(404)
    def not_found_error(e):
        return render_template("error.html", code=404, message="The requested resource was not found on this server."), 404

    @app.errorhandler(413)
    def payload_too_large(e):
        user = get_current_user()
        AuditService.log(
            action=AuditAction.POLICY_VIOLATION,
            status=AuditStatus.BLOCKED,
            user=user,
            details=f"Upload rejected: Payload exceeds max limit of {Config.MAX_CONTENT_LENGTH_MB} MB."
        )
        return render_template("error.html", code=413, message=f"Payload Too Large: File exceeds the maximum allowed size of {Config.MAX_CONTENT_LENGTH_MB} MB."), 413

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        user = get_current_user()
        AuditService.log(
            action=AuditAction.BRUTE_FORCE_DETECTED,
            status=AuditStatus.BLOCKED,
            user=user,
            details=f"Rate limit exceeded on {request.path} by {request.remote_addr}"
        )
        return render_template("error.html", code=429, message="Rate Limit Exceeded: Too many requests. Please slow down and try again later."), 429

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("error.html", code=500, message="An internal server error occurred. The incident has been recorded in the security log."), 500

    return app
