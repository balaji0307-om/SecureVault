import os
import base64
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env file if present
load_dotenv(BASE_DIR / ".env")

class Config:
    """Application configuration with zero-trust security defaults."""

    # Secret key for sessions, CSRF tokens, and cryptographic signing
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY or "replace-with" in SECRET_KEY:
        # Fallback for development only; generates a session-stable development secret
        SECRET_KEY = "dev-insecure-secret-key-change-in-production-vault-992147102481"

    # Master Encryption Key (KEK) - must be 32 bytes (256 bits) for AES-256-GCM
    _raw_master_key = os.environ.get("MASTER_ENCRYPTION_KEY")
    if _raw_master_key and "replace-with" not in _raw_master_key:
        try:
            MASTER_ENCRYPTION_KEY = base64.b64decode(_raw_master_key)
            if len(MASTER_ENCRYPTION_KEY) != 32:
                raise ValueError("Decoded MASTER_ENCRYPTION_KEY must be exactly 32 bytes (256 bits).")
        except Exception:
            # Fallback 32-byte key for local dev if invalid
            MASTER_ENCRYPTION_KEY = b"SECUREVAULT_32_BYTE_DEV_KEY_001!"
    else:
        # Development 32-byte key
        MASTER_ENCRYPTION_KEY = b"SECUREVAULT_32_BYTE_DEV_KEY_001!"

    # Database URI
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'securevault.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Encrypted File Storage
    STORAGE_DIR = Path(os.environ.get("STORAGE_DIR", BASE_DIR / "storage" / "encrypted"))
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    # Isolated Quarantine Storage
    QUARANTINE_DIR = Path(os.environ.get("QUARANTINE_DIR", BASE_DIR / "storage" / "quarantine"))
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    # ClamAV Configuration (daemon / socket / network)
    CLAMAV_ENABLED = os.environ.get("CLAMAV_ENABLED", "false").lower() in ("true", "1", "yes")
    CLAMAV_HOST = os.environ.get("CLAMAV_HOST", "127.0.0.1")
    CLAMAV_PORT = int(os.environ.get("CLAMAV_PORT", 3310))
    CLAMAV_TIMEOUT = int(os.environ.get("CLAMAV_TIMEOUT", 5))

    # Max File Upload Size: 25 MB
    MAX_CONTENT_LENGTH_MB = int(os.environ.get("MAX_CONTENT_LENGTH_MB", 25))
    MAX_CONTENT_LENGTH = MAX_CONTENT_LENGTH_MB * 1024 * 1024

    # Whitelisted extensions for upload validation
    ALLOWED_EXTENSIONS = {
        "txt", "pdf", "png", "jpg", "jpeg", "gif", "svg",
        "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "csv", "zip", "tar", "gz", "json", "xml", "md"
    }

    # Security controls: Brute force & Lockout
    MAX_LOGIN_ATTEMPTS = int(os.environ.get("MAX_LOGIN_ATTEMPTS", 5))
    LOCKOUT_DURATION_MINUTES = int(os.environ.get("LOCKOUT_DURATION_MINUTES", 15))

    # Rate limiting
    RATELIMIT_DEFAULT = "200/day;50/hour"
    LOGIN_RATE_LIMIT = os.environ.get("LOGIN_RATE_LIMIT", "5/minute")

    # Session & Cookie Hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour in seconds
