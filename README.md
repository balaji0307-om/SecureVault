# 🛡️ SecureVault: Zero-Trust-Inspired Secure File-Sharing Platform

> **A Security-Focused Encrypted File-Sharing & Threat Monitoring Platform**  
> *Developed for Cybersecurity Internship Portfolio & Technical Evaluation*

---

## 📋 Executive Overview

**SecureVault** is an enterprise-grade secure file sharing platform architected from the ground up to enforce strict cryptographic boundaries, least-privilege access control, end-to-end integrity verification, and proactive threat detection.

Modern file sharing applications are prime targets for critical vulnerabilities including **Insecure Direct Object References (IDOR)**, **Path Traversal**, **Credential Stuffing / Brute Force**, **Cross-Site Request Forgery (CSRF)**, and **Data Tampering**. SecureVault mitigates these attack vectors through defense-in-depth:

- **Cryptographic Confidentiality**: Per-file ephemeral **AES-256-GCM** Data Encryption Keys (DEKs) wrapped by an environment Master Key (KEK) — envelope encryption ensures that compromise of a single file's key never exposes other files.
- **Path Traversal Resistance**: The platform is **path traversal resistant through UUID-based storage and server-side path validation**, decoupling encrypted blobs from original filenames and storing them outside the web root under random UUIDs (`<uuid>.enc`), neutralizing path and directory traversal attacks.
- **End-to-End Integrity Verification**: Cryptographic **SHA-256** digests are computed prior to encryption and re-verified upon decryption using constant-time comparison (`hmac.compare_digest`), surfacing instantaneous `Integrity: VERIFIED / FAILED` status.
- **Zero-Trust-Inspired Access Control & RBAC**: Enforces a **zero-trust-inspired access control** model with granular role-based access control (Admin vs. Standard User) combined with a fine-grained file permissions matrix (`READ`, `DOWNLOAD`, `EDIT`, `DELETE`, `RESHARE`).
- **Expiring & Burn-After-Reading Links**: Cryptographically signed tokens with configurable TTL, optional password protection, download quotas, and single-use one-time destruction ("LINK ALREADY USED").
- **Classification Policy Enforcement**: Automatic policy engine blocking public share-link generation for `HIGHLY_CONFIDENTIAL` assets.
- **3-Pass Overwrite-Based Secure Deletion**: Implements **3-pass overwrite-based secure deletion for supported storage media** executing a verified 6-step destruction sequence (revoke permissions, invalidate share links, erase key fields, 3-pass disk overwrite with `fsync`, delete record, audit log).
- **Active Threat Defense**: Memory-hard **Argon2id** password hashing, mandatory TOTP 2FA for Administrators, 5-attempt account lockouts (15 minutes), IP rate limiting (5 req/min), rule-based anomaly risk scoring, and immutable security audit trails.

---

## 🏛️ System Architecture

```
                                    ┌───────────────────────────┐
                                    │      Client Browser       │
                                    └─────────────┬─────────────┘
                                                  │ HTTPS / CSP / HSTS / CSRF Token
                                                  ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                    SECUREVAULT CORE                                     │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ [Security Middleware]                                                                   │
│  • Content-Security-Policy (CSP)    • X-Frame-Options: DENY   • X-Content-Type-Options  │
│  • Flask-Limiter (Rate Limiting)    • Flask-WTF (CSRF)        • Referrer-Policy         │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ [Authentication & RBAC]                                                                 │
│  • Argon2id Password Hasher         • Account Lockout Engine  • PyOTP TOTP 2FA          │
│  • Session Hardening (HttpOnly, SameSite=Lax, Strict Auth Guard Decorators)            │
├────────────────────────────┬────────────────────────────┬───────────────────────────────┤
│ [Upload Validation Layer]  │ [Cryptographic Engine]     │ [Threat & Risk Engine]        │
│  • Magic Header Sniffing   │  • AES-256-GCM Envelope    │  • Velocity Spike Detection   │
│  • Extension Whitelist     │  • Master KEK Wrapping     │  • Anomaly Scoring (0-100)    │
│  • Path Traversal Defense  │  • SHA-256 Pre-Hash &      │  • Automated IP & Lockout     │
│    (Sanitize & UUID Store) │    Post-Verify Integrity   │    Action Enforcement         │
└─────────────┬──────────────┴─────────────┬──────────────┴───────────────┬───────────────┘
              │                            │                              │
              ▼                            ▼                              ▼
    ┌──────────────────┐         ┌───────────────────┐          ┌───────────────────┐
    │  SQLite Database │         │  Encrypted Store  │          │ Security Audit    │
    │  (SQLAlchemy)    │         │  (UUID Blobs)     │          │ SIEM Log Stream   │
    │  • Users & RBAC  │         │  • storage/enc/   │          │ • AuditLog Table  │
    │  • File Metadata │         │  • 3-Pass Over-   │          │ • CSV SIEM Export │
    │  • Key Envelopes │         │    write Shredder │          │ • Threat Alerts   │
    └──────────────────┘         └───────────────────┘          └───────────────────┘
```

---

## 🔐 Mapping to the CIA Triad

| CIA Triad Pillar | Threat Vector Addressed | SecureVault Implementation & Mechanism |
| :--- | :--- | :--- |
| **Confidentiality** | Unauthorized data access, disk snooping, database leaks, key compromise | • **AES-256-GCM Envelope Encryption**: Ephemeral 256-bit DEK per file, wrapped by Master KEK.<br>• **Storage Isolation**: Disk files named by random UUIDs (`storage/encrypted/<uuid>.enc`), stored outside web root.<br>• **Password Security**: Argon2id memory-hard salted hashes (`$argon2id$`).<br>• **TOTP 2FA**: Mandatory for Administrators, optional for Users.<br>• **Data Classification**: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `HIGHLY_CONFIDENTIAL` with policy gate blocking public links for highly confidential data. |
| **Integrity** | Ciphertext tampering, bit-flipping, file corruption, malicious payload substitution | • **GCM Authenticated Encryption**: 12-byte random nonce + 16-byte authentication tag detects any in-flight byte modification.<br>• **SHA-256 Pre-Encryption Digest**: Computed on raw payload before ciphering; recalculated and compared via constant-time `hmac.compare_digest` check upon every download.<br>• **Strict Header Validation**: Magic bytes checked to prevent executable masquerading (.exe renamed to .pdf).<br>• **Path Traversal Resistance**: Path traversal resistant through UUID-based storage and server-side path validation. |
| **Availability** | Denial of Service (DoS), brute-force credential stuffing, disk exhaustion | • **IP Rate Limiting**: Flask-Limiter enforces 5 requests/minute on sensitive routes (`/auth/login`).<br>• **Account Lockout**: 5 failed login attempts trigger an immediate 15-minute account lock (`ACCOUNT_LOCKED` & `BRUTE_FORCE_DETECTED`).<br>• **Payload Quotas**: Strict 25 MB file upload ceiling rejects memory/disk exhaustion.<br>• **Secure Deletion**: 3-pass overwrite-based secure deletion for supported storage media prevents lingering orphaned blobs and disk leaks. |

---

## 🛡️ OWASP Top 10 Mitigations Matrix

| OWASP Vulnerability | Threat Scenario | SecureVault Defense Architecture |
| :--- | :--- | :--- |
| **A01: Broken Access Control** | Non-owner accesses another user's private file (IDOR) | • Random UUID primary keys prevent sequential ID guessing.<br>• Ownership check in every file endpoint; returns `403 Forbidden` if user is neither owner, admin, nor granted explicit permission.<br>• Non-admin users blocked from SOC endpoints (`/admin`, `/security/*`). |
| **A02: Cryptographic Failures** | Hardcoded keys, weak DES/RC4 ciphers, leaked master keys | • AES-256-GCM cipher with random 96-bit nonces.<br>• Master key loaded exclusively from environment variable `MASTER_ENCRYPTION_KEY`.<br>• File keys wrapped under envelope encryption pattern. |
| **A03: Injection** | SQL Injection via filename or share tokens | • SQLAlchemy ORM parameterized queries prevent SQL injection.<br>• `secure_filename()` sanitizes all user input strings.<br>• Jinja2 auto-escaping prevents Cross-Site Scripting (XSS). |
| **A04: Insecure Design** | Unlimited password guessing & brute force | • 5-attempt account lockout for 15 minutes.<br>• IP rate limiting via Flask-Limiter.<br>• Mandatory TOTP 2FA step-up for administrator accounts. |
| **A05: Security Misconfiguration** | Clickjacking, MIME sniffing, unvalidated headers | • Security Response Headers middleware enforces `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Strict-Transport-Security`. |
| **A07: Identification & Auth Failures** | Weak passwords, compromised sessions | • Argon2id password hashing with time cost 3, memory cost 64 MB, parallelism 4.<br>• Session cookies hardened with `HttpOnly=True`, `SameSite=Lax`, and `Secure` flags. |
| **A08: Software & Data Integrity Failures** | Malicious file upload / Tampered disk storage | • Pre-encryption SHA-256 digest verified at every download via constant-time comparison.<br>• Tampered disk blobs fail AES-GCM tag verification and raise alert.<br>• File extension whitelist and binary magic header validation. |
| **Path Traversal (`../../etc/passwd`)** | User attempts to overwrite or read server system files | • **Path traversal resistant through UUID-based storage and server-side path validation**.<br>• Filename sanitizer strictly rejects `..`, `/`, `\`, and null bytes.<br>• Disk storage ignores original filename entirely and uses `uuid.uuid4().hex + '.enc'`. |

---

## 📁 Project Structure

```
SecureVault/
├── app/
│   ├── __init__.py                 # Application factory, security middleware, error handlers
│   ├── config.py                   # Environment config, quarantine path, ClamAV toggle
│   ├── extensions.py               # SQLAlchemy, CSRFProtect, Flask-Limiter singletons
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py                 # User model (Argon2id, lockout, 2FA, roles)
│   │   ├── user_session.py         # Concurrent session model (device parsing, revocation, IP/UA audit)
│   │   ├── file.py                 # File model (UUID, encrypted DEK, nonces, SHA-256, classification)
│   │   ├── permission.py           # Fine-grained permissions (READ, DOWNLOAD, EDIT, DELETE, RESHARE)
│   │   ├── share_link.py           # Share links (signed token, expiry, max-downloads, password, one-time)
│   │   └── audit_log.py            # Immutable security audit trail with severity classification (CRITICAL-INFO)
│   ├── routes/
│   │   ├── auth.py                 # Register, Login, Sessions management, Remote Revocation, 2FA
│   │   ├── files.py                # Upload (malware scan), Download (step-up reauth), Secure Shred
│   │   ├── sharing.py              # Share links, Public access, Password challenges, Permission management
│   │   ├── admin.py                # Security Operations Center (SOC), User management, Account unlocking
│   │   └── security.py             # Filterable audit log explorer, SIEM CSV export, Risk alerts
│   ├── services/
│   │   ├── encryption.py           # AES-256-GCM envelope encryption, SHA-256 verifier
│   │   ├── malware_scanner.py      # Malware pipeline (EICAR detection, macros, quarantine, optional ClamAV)
│   │   ├── secure_delete.py        # 3-pass overwrite-based secure deletion for supported storage media
│   │   ├── file_validator.py       # Extension whitelist, executable header detection (PE/ELF), path sanitizer
│   │   ├── security_posture.py     # Live dynamic inspection of all 14 platform security controls
│   │   ├── share_service.py        # Token generation, expiration validation, classification policy gate
│   │   ├── audit_service.py        # Centralized security audit logger with severity classification
│   │   └── risk_engine.py          # Suspicious activity scoring (download bursts, IP anomalies)
│   ├── templates/
│   │   ├── base.html               # Security-hardened layout, CSP-compliant, CSRF meta
│   │   ├── login.html              # Login form with rate limit & lockout alerts
│   │   ├── register.html           # Password policy checklist
│   │   ├── setup_2fa.html          # TOTP setup with QR code
│   │   ├── verify_2fa.html         # TOTP 6-digit challenge
│   │   ├── sessions.html           # Concurrent active sessions & remote revocation UI
│   │   ├── reauth_download.html    # Step-up re-authentication challenge for HIGHLY_CONFIDENTIAL assets
│   │   ├── dashboard.html          # User security dashboard & quick upload
│   │   ├── files.html              # Encrypted vault file explorer with classification filters
│   │   ├── share.html              # Share link & RBAC permission manager
│   │   ├── share_access.html       # Public share landing & download page (one-time burn notification)
│   │   ├── admin.html              # SOC security metrics, recent events stream, posture overview
│   │   ├── admin_users.html        # User account management & lockout unlocking
│   │   ├── audit_logs.html         # Filterable audit trail explorer with severity badges
│   │   ├── risk_alerts.html        # Threat & risk alert monitoring
│   │   └── error.html              # Custom security error template (400, 403, 404, 413, 429, 500)
│   ├── static/
│   │   ├── css/style.css           # Cybersecurity dark/neon design system
│   │   └── js/main.js              # Clipboard helpers & UI interactions
│   └── utils/
│       └── auth.py                 # @login_required, @admin_required, session tracker, user resolver
├── storage/
│   ├── encrypted/                  # Encrypted ciphertext storage (.gitignore protected)
│   └── quarantine/                 # Isolated malware quarantine vault (.gitignore protected)
├── tests/
│   ├── conftest.py                 # Pytest fixtures, test database, test client
│   ├── test_auth.py                # Argon2, lockout, rate limiting, concurrent session revocation
│   ├── test_files.py               # Envelope encryption, SHA-256 integrity, shredding, PE spoofing, malware quarantine
│   ├── test_access_control.py      # IDOR prevention, permission matrix, step-up download reauth
│   ├── test_sharing.py             # Expired links, one-time burn links, password links, classification policy
│   └── test_security.py            # CSRF, path traversal, security headers, risk engine, audit severity
├── .env.example                    # Environment variable template
├── requirements.txt                # Pinned dependencies
├── run.py                          # Server launcher with initial seed accounts
├── VERIFICATION.md                 # Complete line-by-line proof & verification matrix
├── README.md                       # Comprehensive documentation
└── .gitignore                      # Ignore venv, secrets, DB, and ciphertext blobs
```

---

## 🚀 Installation & Setup Guide

### 1. Prerequisites
- Python 3.10, 3.11, or 3.12
- Git

### 2. Clone & Setup Virtual Environment
```bash
git clone <repository-url>
cd "Secure File-Sharing Application"

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy the template configuration to `.env`:
```bash
# Windows:
copy .env.example .env
# Linux / macOS:
cp .env.example .env
```
Generate strong random production keys:
```bash
# Generate SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# Generate MASTER_ENCRYPTION_KEY (32 bytes, Base64)
python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```
Paste these values into your `.env` file.

### 5. Launch SecureVault
```bash
python run.py
```
SecureVault will initialize database tables and automatically seed demonstration accounts:
- **Administrator Account**: Username: `admin` | Password: `AdminPass123!`
- **Standard User Account**: Username: `alice` | Password: `AlicePass123!`
- **Web Interface**: `http://127.0.0.1:5000`

---

## 🧪 Running the Security Test Suite

The security test suite comprehensively validates authentication, cryptographic envelope operations, IDOR defenses, one-time links, CSRF, and path traversal protection:

```bash
# Run all security tests with verbose output
python -m pytest -v tests/
```

### Test Suite Coverage:
```
tests/test_access_control.py::test_idor_non_owner_blocked_from_download PASSED
tests/test_access_control.py::test_fine_grained_permission_grant_and_enforcement PASSED
tests/test_access_control.py::test_admin_can_download_any_file PASSED
tests/test_access_control.py::test_regular_user_blocked_from_admin_center PASSED
tests/test_access_control.py::test_highly_confidential_download_requires_step_up_reauth PASSED
tests/test_auth.py::test_argon2_password_hashing PASSED
tests/test_auth.py::test_user_registration PASSED
tests/test_auth.py::test_login_success_and_logout PASSED
tests/test_auth.py::test_account_lockout_after_five_failed_attempts PASSED
tests/test_auth.py::test_rate_limiting_triggers_429 PASSED
tests/test_auth.py::test_concurrent_session_tracking_and_revocation PASSED
tests/test_files.py::test_upload_valid_file_envelope_encrypted PASSED
tests/test_files.py::test_download_and_integrity_verification PASSED
tests/test_files.py::test_disallowed_extension_rejection PASSED
tests/test_files.py::test_renamed_executable_spoofing_rejected PASSED
tests/test_files.py::test_eicar_malware_detection_and_quarantine PASSED
tests/test_files.py::test_tampered_blob_integrity_failure PASSED
tests/test_files.py::test_secure_shredding_deletion PASSED
tests/test_security.py::test_csrf_protection_enforced PASSED
tests/test_security.py::test_path_traversal_prevention PASSED
tests/test_security.py::test_path_traversal_upload_rejected PASSED
tests/test_security.py::test_security_headers_enforced_on_responses PASSED
tests/test_security.py::test_risk_engine_anomaly_detection PASSED
tests/test_security.py::test_audit_severity_classification PASSED
tests/test_sharing.py::test_share_link_creation_and_download PASSED
tests/test_sharing.py::test_expired_share_link_rejected PASSED
tests/test_sharing.py::test_one_time_burn_link_invalidated_after_download PASSED
tests/test_sharing.py::test_password_protected_share_link PASSED
tests/test_sharing.py::test_highly_confidential_policy_blocks_public_share_links PASSED

======================= 29 passed in ~21s =======================
```

---

## 🎬 Demonstration Walkthrough Guide

### Demo Scenario A: Standard User Flow (Encryption & Sharing)
1. **Login**: Navigate to `http://127.0.0.1:5000/auth/login` and sign in as `alice` (`AlicePass123!`).
2. **Encrypted Upload**:
   - In the Dashboard upload section, choose any document (e.g. `audit_plan.pdf` or `notes.txt`).
   - Select the classification tier (e.g. `CONFIDENTIAL`).
   - Click **Encrypt & Store**.
   - Notice the disk storage: the file is stored under a random UUID (e.g. `3a4f...enc`) in `storage/encrypted/`. The original filename is never exposed on the filesystem.
3. **Download with Integrity Check**:
   - Click **Download**.
   - The server unwraps the DEK using the Master KEK, decrypts the blob via AES-256-GCM, recomputes the SHA-256 hash, verifies that it matches the stored pre-encryption digest, and delivers the file with the HTTP header `X-File-Integrity: VERIFIED`.
4. **Create a One-Time "Burn-After-Reading" Share Link**:
   - Click **Share** next to the file.
   - Check **One-Time Link ("Burn After Reading")**.
   - Click **Create Secure Share Link**.
   - Copy the generated share link.
   - Open a Private / Incognito browser window and navigate to the link.
   - Click **Decrypt & Download File**. The file downloads successfully.
   - Refresh the link in the browser — SecureVault immediately displays: **`LINK ALREADY USED (One-time link has been consumed)`**.
5. **Zero-Trust Classification Policy**:
   - Upload a file and set classification to **`HIGHLY_CONFIDENTIAL`**.
   - Click **Share** on that file — notice the public link generator is disabled and displays a policy alert: *Files classified as HIGHLY_CONFIDENTIAL are strictly prohibited from being shared via public links.* Direct user permissions must be granted instead.

---

### Demo Scenario B: Administrator & Security Dashboard Flow
1. **Login**: Sign in as `admin` (`AdminPass123!`).
2. **Mandatory 2FA**:
   - Administrator accounts are automatically prompted for TOTP Two-Factor setup.
   - Scan the QR code using Google Authenticator, Authy, or enter the manual key.
   - Enter the 6-digit TOTP code to activate.
3. **Security Operations Center (SOC)**:
   - Click **Admin Center** in the navigation bar.
   - View live telemetry metrics: **Enrolled Users**, **Encrypted Blobs**, **Failed Logins (24h)**, **Blocked Requests (24h)**, **Live Threat Posture** (LOW/MEDIUM/HIGH), and **Active Share Links**.
   - Review the **Cryptographic & Platform Posture** panel detailing AES-256-GCM envelope specs and Argon2id parameters.
4. **Trigger Brute-Force Lockout Defense**:
   - In another browser or incognito window, attempt to log in as `alice` with the wrong password 5 consecutive times.
   - On the 5th attempt, SecureVault locks the account for 15 minutes and records audit events: `ACCOUNT_LOCKED` and `BRUTE_FORCE_DETECTED`.
   - Attempting a 6th login displays: *Security Lockout: Account is temporarily locked*.
5. **Admin Account Unlocking**:
   - Return to the Admin portal and navigate to **User Management** (`/admin/users`).
   - Notice `alice` is marked as **LOCKED** with a countdown timer.
   - Click **Unlock** to immediately clear the lockout and restore access.
6. **Audit Trail Explorer & SIEM Export**:
   - Click **Audit Trail** (`/security/audit`).
   - Filter by action (e.g. `BRUTE_FORCE_DETECTED`, `FILE_UPLOADED`, `UNAUTHORIZED_ACCESS`).
   - Click **Export SIEM CSV** to download a structured incident report.

---

### Demo Scenario C: Advanced Security Add-Ons & Threat Mitigation
1. **Malware Scanning & Quarantine Isolation**:
   - Attempt to upload an EICAR test file (`sample_eicar.txt` containing the standard EICAR test string).
   - SecureVault detects the signature before encryption, halts storage in the main encrypted directory, moves the payload into `storage/quarantine/<uuid>.quarantine`, logs a `CRITICAL` severity audit incident (`MALWARE_DETECTED`), and displays: *Malware detected! File has been isolated in quarantine and rejected.*
2. **Deep Binary Spoofing Defense**:
   - Rename an executable binary (`calc.exe`) to `financial_statement.pdf` and attempt upload.
   - The file validator detects the `MZ` DOS/PE signature, rejects the payload as a disguised executable, and logs an alert.
3. **Active Concurrent Session Management & Remote Revocation**:
   - Log in on two different browsers or devices (e.g. Chrome on Windows and Safari on Mobile).
   - Navigate to **Sessions** (`/auth/sessions`) on either device.
   - View the enrolled devices list with parsed browser, OS, IP address, and status badges.
   - Click **Revoke** next to the remote session — the remote session is immediately marked as revoked in the database and forced to re-authenticate on its next request.
4. **Step-Up Re-Authentication for Highly Confidential Assets**:
   - As `alice`, upload a document classified as **`HIGHLY_CONFIDENTIAL`**.
   - Click **Download**. Instead of immediate delivery, SecureVault prompts with a step-up re-authentication challenge (`/files/<id>/reauth`).
   - Entering the correct account password unlocks a temporary download clearance and decrypts the file.
5. **Security Severity Classification & SIEM Integration**:
   - Navigate to **Audit Trail** (`/security/audit`).
   - Observe the colored severity badges: `CRITICAL` (red), `HIGH` (orange), `MEDIUM` (amber), `LOW` (cyan), and `INFO` (blue).
   - Threat events are prioritized and exportable to CSV for external SIEM consumption.

---

## 🔒 Security Specifications Summary

| Feature | Specification / Algorithm | Standard / Defensibility Basis |
| :--- | :--- | :--- |
| **Symmetric Encryption** | AES-256-GCM (Envelope Encryption) | NIST SP 800-38D |
| **Data Encryption Key (DEK)** | 256-bit cryptographically secure random (`os.urandom(32)`) | FIPS 140-2 |
| **Nonce Generation** | 96-bit unique random per encryption (`os.urandom(12)`) | NIST SP 800-38D |
| **Key Wrapping (KEK)** | AES-256-GCM Master Key wrapping | NIST SP 800-38F |
| **Password Hashing** | Argon2id (`t=3, m=64MB, p=4, salt=16B`) | RFC 9106 (PHC Winner) |
| **File Integrity** | SHA-256 Pre-Digest + Constant-Time `hmac.compare_digest` | FIPS 180-4 |
| **Secure Deletion** | 3-pass overwrite-based secure deletion for supported storage media (Random / Null / Random) + `fsync` | 3-pass overwrite-based secure deletion for supported storage media |
| **Path Traversal Defense** | UUID blob decoupling (`<uuid>.enc`) + strict server-side sequence rejection | Path traversal resistant through UUID-based storage and server-side path validation |
| **Access Control** | Fine-grained RBAC matrix (`READ`, `DOWNLOAD`, `EDIT`, `DELETE`, `RESHARE`) + IDOR checks | Zero-trust-inspired access control |
| **Two-Factor Auth** | Time-based One-Time Password (TOTP) | RFC 6238 |
| **Anti-CSRF** | Cryptographically signed session tokens (Flask-WTF) | OWASP CSRF Guide |
| **Rate Limiting** | Sliding window rate limiter (Flask-Limiter / limits) | OWASP Automated Threats |

---

## 📜 License & Evaluation Notice
This software is developed strictly for educational, security demonstration, and internship evaluation purposes.
All cryptographic primitives utilize peer-reviewed, standard implementations from Python `cryptography` and `argon2-cffi`.
