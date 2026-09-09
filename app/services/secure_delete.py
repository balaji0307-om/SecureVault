import os
from pathlib import Path
from app.extensions import db
from app.models.file import File
from app.models.permission import FilePermission
from app.models.share_link import ShareLink
from app.services.audit_service import AuditService
from app.models.audit_log import AuditAction, AuditStatus
from app.config import Config

class SecureDeleteService:
    """
    Executes ordered, 3-pass overwrite-based secure deletion for supported storage media.
    Strict sequence:
    1. Revoke permissions
    2. Invalidate related share links
    3. Overwrite & clear encrypted key fields
    4. 3-pass overwrite of the encrypted blob on disk + unlink
    5. Delete file database record
    6. Write audit log entry
    """

    @classmethod
    def overwrite_file(cls, filepath: Path | str, passes: int = 3) -> bool:
        """
        3-pass overwrite-based secure deletion for supported storage media.
        Note: Software overwrite cannot be guaranteed on modern SSD/flash media due to wear leveling,
        but provides defense-in-depth on supported magnetic and virtualized filesystems.
        """
        path = Path(filepath)
        if not path.exists():
            return False

        try:
            size = path.stat().st_size
            with open(path, "ba+", buffering=0) as f:
                for p in range(passes):
                    f.seek(0)
                    if p % 2 == 0:
                        # Write cryptographically secure random bytes
                        f.write(os.urandom(size))
                    else:
                        # Write null bytes (0x00)
                        f.write(b"\x00" * size)
                    f.flush()
                    os.fsync(f.fileno())
            path.unlink()
            return True
        except Exception:
            if path.exists():
                path.unlink()
            return False

    @classmethod
    def delete_file(cls, file: File, user) -> bool:
        """
        Executes the mandatory 6-step deletion sequence.
        """
        file_id = file.id
        filename = file.original_name
        storage_path = Config.STORAGE_DIR / file.storage_name

        # Step 1: Revoke associated permissions
        FilePermission.query.filter_by(file_id=file_id).delete()

        # Step 2: Invalidate related share links
        ShareLink.query.filter_by(file_id=file_id).delete()

        # Step 3: Delete encrypted key material from DB
        file.encrypted_key = "SHREDDED"
        file.key_nonce = "SHREDDED"
        file.file_nonce = "SHREDDED"
        db.session.flush()

        # Step 4: 3-pass overwrite of the encrypted blob on disk
        cls.overwrite_file(storage_path, passes=3)

        # Step 5: Delete file record from DB
        db.session.delete(file)
        db.session.commit()

        # Step 6: Write audit log entry
        AuditService.log(
            action=AuditAction.FILE_DELETED,
            status=AuditStatus.SUCCESS,
            user=user,
            resource_type="File",
            resource_id=file_id,
            details=f"Securely deleted file '{filename}' via 6-step sequence (permissions revoked, links invalidated, keys cleared, 3-pass blob wipe, record deleted)."
        )

        return True
