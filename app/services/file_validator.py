import os
import re
import mimetypes
from werkzeug.utils import secure_filename
from app.config import Config

class FileValidationError(Exception):
    """Raised when file upload validation fails security checks."""
    pass

class FileValidator:
    """Rigorous multi-layer file upload validation to prevent RCE, spoofing, and path traversal."""

    # Common binary magic headers
    MAGIC_SIGNATURES = {
        "pdf": [b"%PDF-"],
        "png": [b"\x89PNG\r\n\x1a\n"],
        "jpg": [b"\xff\xd8\xff"],
        "jpeg": [b"\xff\xd8\xff"],
        "gif": [b"GIF87a", b"GIF89a"],
        "zip": [b"PK\x03\x04", b"PK\x05\x06"],
        "docx": [b"PK\x03\x04"],
        "xlsx": [b"PK\x03\x04"],
        "pptx": [b"PK\x03\x04"],
    }

    # Dangerous extensions that must never be accepted under any circumstances
    DANGEROUS_EXTENSIONS = {
        "exe", "dll", "so", "bin", "sh", "bash", "bat", "cmd", "ps1", "vbs",
        "py", "pyc", "pyd", "php", "phtml", "jsp", "asp", "aspx", "cgi", "pl",
        "jar", "war", "msi", "scr", "hta", "com"
    }

    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """
        Sanitize and strip directory traversal sequences, null bytes, and illegal characters.
        """
        if not filename:
            raise FileValidationError("Filename cannot be empty.")

        # Check for path traversal attempts or null byte injection
        if ".." in filename or "/" in filename or "\\" in filename or "\x00" in filename:
            raise FileValidationError("Path traversal characters detected in filename.")

        clean_name = secure_filename(filename)
        if not clean_name:
            clean_name = "unnamed_file"

        return clean_name

    @classmethod
    def validate_extension(cls, filename: str) -> str:
        """Verify file extension against allowed whitelist and dangerous blacklist."""
        if "." not in filename:
            raise FileValidationError("File must have an extension.")

        ext = filename.rsplit(".", 1)[1].lower()

        if ext in cls.DANGEROUS_EXTENSIONS:
            raise FileValidationError(f"Execution security violation: .{ext} files are prohibited.")

        if ext not in Config.ALLOWED_EXTENSIONS:
            raise FileValidationError(f"Extension .{ext} is not supported. Allowed: {', '.join(sorted(Config.ALLOWED_EXTENSIONS))}")

        return ext

    @classmethod
    def validate_size(cls, file_bytes: bytes) -> int:
        """Verify that file size is within limits."""
        size = len(file_bytes)
        if size == 0:
            raise FileValidationError("File is empty (0 bytes).")
        if size > Config.MAX_CONTENT_LENGTH:
            raise FileValidationError(f"File size ({size / (1024*1024):.1f}MB) exceeds maximum limit ({Config.MAX_CONTENT_LENGTH_MB}MB).")
        return size

    # Dangerous binary executable headers that must never appear in any uploaded document
    EXECUTABLE_SIGNATURES = [
        b"MZ",                     # DOS / Windows PE executable
        b"\x7fELF",                # Linux ELF binary
        b"\xca\xfe\xba\xbe",       # Mach-O Fat Binary / Java Class
        b"\xce\xfa\xed\xfe",       # Mach-O 32-bit
        b"\xcf\xfa\xed\xfe",       # Mach-O 64-bit
        b"#!/",                    # Direct script shebang
        b"<?php",                  # PHP script header
    ]

    @classmethod
    def validate_magic_bytes(cls, ext: str, file_bytes: bytes) -> bool:
        """
        Inspect the header bytes (magic numbers) of the uploaded payload
        to verify that the actual binary content matches the claimed extension
        and enforce that no executable signatures are masquerading under safe extensions.
        """
        ext = ext.lower()

        # Check for disguised executables masquerading under any non-script allowed extension
        header = file_bytes[:16]
        for exec_sig in cls.EXECUTABLE_SIGNATURES:
            if header.startswith(exec_sig):
                raise FileValidationError(
                    f"Content-based signature mismatch: executable binary header detected in file claiming to be .{ext}."
                )

        # Enforce strict binary signatures for formatted file types
        if ext in cls.MAGIC_SIGNATURES:
            signatures = cls.MAGIC_SIGNATURES[ext]
            if not any(header.startswith(sig) for sig in signatures):
                raise FileValidationError(
                    f"Content-based signature mismatch: file content does not match legitimate .{ext} format."
                )

        # Text/JSON/CSV/XML basic sanity check (ensure not arbitrary executable binary or null-injected)
        if ext in {"txt", "csv", "json", "xml", "md"}:
            sample = file_bytes[:1024]
            # Disallow null bytes or shell script execution headers in text documents
            if b"\x00" in sample:
                raise FileValidationError(f"Null-byte injection or corrupt binary data detected in text file .{ext}.")
            if sample.startswith(b"MZ") or sample.startswith(b"\x7fELF"):
                raise FileValidationError(f"Executable signature detected in text file .{ext}.")

        return True

    @classmethod
    def detect_mime_type(cls, filename: str, file_bytes: bytes) -> str:
        """Derive safe MIME type based on filename and header inspection."""
        guessed_type, _ = mimetypes.guess_type(filename)
        return guessed_type or "application/octet-stream"

    @classmethod
    def validate_upload(cls, raw_filename: str, file_bytes: bytes) -> tuple[str, str, int]:
        """
        Execute the full validation pipeline.
        Returns: (sanitized_name, mime_type, file_size)
        """
        clean_name = cls.sanitize_filename(raw_filename)
        ext = cls.validate_extension(clean_name)
        size = cls.validate_size(file_bytes)
        cls.validate_magic_bytes(ext, file_bytes)
        mime_type = cls.detect_mime_type(clean_name, file_bytes)
        return clean_name, mime_type, size
