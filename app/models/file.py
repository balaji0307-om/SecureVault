import uuid
from datetime import datetime, timezone
from app.extensions import db

class Classification:
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    HIGHLY_CONFIDENTIAL = "HIGHLY_CONFIDENTIAL"

    ALL = [PUBLIC, INTERNAL, CONFIDENTIAL, HIGHLY_CONFIDENTIAL]

class File(db.Model):
    __tablename__ = "files"

    # UUID primary key prevents sequential ID enumeration (IDOR mitigation)
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Internal disk storage identifier - never exposes original filename or user path
    storage_name = db.Column(db.String(64), unique=True, nullable=False, default=lambda: f"{uuid.uuid4().hex}.enc")
    
    # User metadata
    original_name = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(128), nullable=False, default="application/octet-stream")
    file_size = db.Column(db.BigInteger, nullable=False)  # Size in bytes
    
    # File integrity: SHA-256 pre-encryption digest for end-to-end verification
    sha256_hash = db.Column(db.String(64), nullable=False, index=True)
    
    # Data classification policy tag
    classification = db.Column(db.String(32), nullable=False, default=Classification.INTERNAL)
    
    # AES-256-GCM Envelope Encryption fields (Base64 encoded strings)
    encrypted_key = db.Column(db.Text, nullable=False)  # DEK encrypted by master KEK
    key_nonce = db.Column(db.String(64), nullable=False)  # Nonce used for DEK encryption
    file_nonce = db.Column(db.String(64), nullable=False)  # Nonce used for File payload encryption

    # Ownership & Timestamps
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    owner = db.relationship("User", back_populates="files")
    permissions = db.relationship("FilePermission", back_populates="file", cascade="all, delete-orphan")
    share_links = db.relationship("ShareLink", back_populates="file", cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        if "id" not in kwargs:
            kwargs["id"] = str(uuid.uuid4())
        if "storage_name" not in kwargs:
            kwargs["storage_name"] = f"{uuid.uuid4().hex}.enc"
        super().__init__(**kwargs)

    @property
    def is_highly_confidential(self) -> bool:
        return self.classification == Classification.HIGHLY_CONFIDENTIAL


    def __repr__(self):
        return f"<File {self.original_name} (ID: {self.id}, Classification: {self.classification})>"
