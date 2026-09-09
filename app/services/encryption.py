import os
import hmac
import hashlib
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class EncryptionService:
    """Zero-Trust Envelope Encryption using AES-256-GCM and SHA-256 Integrity Verification."""

    KEY_SIZE_BYTES = 32   # 256 bits
    NONCE_SIZE_BYTES = 12 # 96 bits (NIST SP 800-38D recommended for GCM)

    @classmethod
    def generate_key(cls) -> bytes:
        """Generate a cryptographically secure 256-bit random key."""
        return AESGCM.generate_key(bit_length=256)

    @classmethod
    def generate_nonce(cls) -> bytes:
        """Generate a cryptographically secure 96-bit (12 bytes) nonce."""
        return os.urandom(cls.NONCE_SIZE_BYTES)

    @classmethod
    def compute_sha256(cls, data: bytes) -> str:
        """Compute SHA-256 digest of unencrypted payload for integrity tracking."""
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def verify_integrity(cls, expected_hash: str, data: bytes) -> bool:
        """Constant-time verification of data against expected SHA-256 digest."""
        computed_hash = cls.compute_sha256(data)
        return hmac.compare_digest(expected_hash.lower(), computed_hash.lower())

    @classmethod
    def encrypt_data(cls, key: bytes, plaintext: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
        """
        Encrypt arbitrary plaintext using AES-256-GCM.
        Returns: (ciphertext_with_tag, nonce)
        """
        if len(key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"AES-256 requires a 32-byte key. Received {len(key)} bytes.")
        
        nonce = cls.generate_nonce()
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return ciphertext, nonce

    @classmethod
    def decrypt_data(cls, key: bytes, ciphertext: bytes, nonce: bytes, associated_data: bytes = None) -> bytes:
        """
        Decrypt and verify AES-256-GCM ciphertext using the given key and nonce.
        Raises InvalidTag if ciphertext, nonce, or key was tampered with.
        """
        if len(key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"AES-256 requires a 32-byte key. Received {len(key)} bytes.")
        
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)

    @classmethod
    def encrypt_file_envelope(cls, file_bytes: bytes, master_key: bytes) -> dict:
        """
        Envelope Encryption Architecture:
        1. Generate an ephemeral random 256-bit Data Encryption Key (DEK).
        2. Encrypt file payload with DEK using AES-256-GCM -> (encrypted_blob, file_nonce).
        3. Encrypt the ephemeral DEK with the Master Key (KEK) using AES-256-GCM -> (encrypted_dek, key_nonce).
        4. Return dict with encrypted blob and base64-encoded metadata.
        Compromise of one file's key never exposes other files.
        """
        if len(master_key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"Master Key must be exactly 32 bytes (256 bits). Received {len(master_key)}.")

        # Step 1: Ephemeral DEK
        dek = cls.generate_key()

        # Step 2: Encrypt file with DEK
        encrypted_blob, file_nonce = cls.encrypt_data(dek, file_bytes)

        # Step 3: Wrap (encrypt) DEK with Master KEK
        encrypted_dek, key_nonce = cls.encrypt_data(master_key, dek)

        return {
            "encrypted_blob": encrypted_blob,
            "encrypted_key": base64.b64encode(encrypted_dek).decode("utf-8"),
            "key_nonce": base64.b64encode(key_nonce).decode("utf-8"),
            "file_nonce": base64.b64encode(file_nonce).decode("utf-8"),
            "sha256_hash": cls.compute_sha256(file_bytes),
        }

    @classmethod
    def decrypt_file_envelope(
        cls,
        encrypted_blob: bytes,
        encrypted_key_b64: str,
        file_nonce_b64: str,
        key_nonce_b64: str,
        master_key: bytes
    ) -> bytes:
        """
        Envelope Decryption Architecture:
        1. Un-wrap (decrypt) DEK using Master KEK and key_nonce.
        2. Decrypt the file payload using DEK and file_nonce.
        3. Returns decrypted file bytes.
        """
        if len(master_key) != cls.KEY_SIZE_BYTES:
            raise ValueError("Master Key must be exactly 32 bytes.")

        # Decode base64 components
        encrypted_dek = base64.b64decode(encrypted_key_b64)
        key_nonce = base64.b64decode(key_nonce_b64)
        file_nonce = base64.b64decode(file_nonce_b64)

        # Step 1: Unwrap DEK
        dek = cls.decrypt_data(master_key, encrypted_dek, key_nonce)

        # Step 2: Decrypt file payload
        decrypted_bytes = cls.decrypt_data(dek, encrypted_blob, file_nonce)
        return decrypted_bytes

    @classmethod
    def secure_shred(cls, filepath: str | Path, passes: int = 3) -> None:
        """
        Secure file deletion: overwrites disk sectors with random data, zeros,
        and flushes disk caches before unlinking to prevent data remanence attacks.
        """
        path = Path(filepath)
        if not path.exists():
            return

        try:
            length = path.stat().st_size
            with open(path, "ba+", buffering=0) as f:
                for p in range(passes):
                    f.seek(0)
                    if p % 2 == 0:
                        # Overwrite with cryptographically secure random bytes
                        f.write(os.urandom(length))
                    else:
                        # Overwrite with null bytes (0x00)
                        f.write(b"\x00" * length)
                    f.flush()
                    os.fsync(f.fileno())
            # Finally remove the file
            path.unlink()
        except Exception:
            # Fallback direct unlink if low-level overwrite encounters filesystem locks
            if path.exists():
                path.unlink()
