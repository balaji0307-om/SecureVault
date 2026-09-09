from datetime import datetime, timezone
from app.extensions import db

class PermissionType:
    READ = "READ"
    DOWNLOAD = "DOWNLOAD"
    EDIT = "EDIT"
    DELETE = "DELETE"
    RESHARE = "RESHARE"

    ALL = [READ, DOWNLOAD, EDIT, DELETE, RESHARE]

class FilePermission(db.Model):
    __tablename__ = "file_permissions"
    __table_args__ = (
        db.UniqueConstraint("file_id", "user_id", "permission", name="uq_file_user_permission"),
    )

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.String(36), db.ForeignKey("files.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    permission = db.Column(db.String(20), nullable=False)  # READ, DOWNLOAD, EDIT, DELETE, RESHARE
    granted_by_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    file = db.relationship("File", back_populates="permissions")
    user = db.relationship("User", foreign_keys=[user_id], back_populates="permissions")
    granted_by = db.relationship("User", foreign_keys=[granted_by_id])

    def __repr__(self):
        return f"<FilePermission File:{self.file_id} User:{self.user_id} Perm:{self.permission}>"
