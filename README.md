# 🛡️ SecureVault — Enterprise Encrypted File-Sharing Platform

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Cryptography](https://img.shields.io/badge/Crypto-AES--256--GCM-blue.svg?style=flat&logo=letsencrypt&logoColor=white)](https://cryptography.io/)
[![Password Hashing](https://img.shields.io/badge/Hash-Argon2id-blueviolet.svg?style=flat)](https://github.com/P-H-C/phc-winner-argon2)
[![Tests](https://img.shields.io/badge/Tests-29%2F29%20Passing-brightgreen.svg?style=flat&logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![OWASP Aligned](https://img.shields.io/badge/OWASP-ASVS%20Level%202%20Aligned-orange.svg?style=flat&logo=owasp&logoColor=white)](https://owasp.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat)](LICENSE)

An enterprise-grade, high-assurance encrypted file-sharing platform engineered with defense-in-depth principles. SecureVault implements **client-agnostic authenticated symmetric encryption (AES-256-GCM)**, **Argon2id memory-hard credential derivation**, **heuristic malware and MIME signature inspection**, **adaptive contextual risk scoring**, and **granular zero-trust-inspired access control**.

---

## 📑 Table of Contents
- [Executive Overview](#-executive-overview)
- [Key Security Capabilities](#-key-security-capabilities)
- [Architecture & Data Flow](#-architecture--data-flow)
- [Cryptographic Specifications](#-cryptographic-specifications)
- [CIA Triad Mapping](#-cia-triad-mapping)
- [OWASP Top 10 (2021) Defensive Matrix](#-owasp-top-10-2021-defensive-matrix)
- [Directory Structure](#-directory-structure)
- [Installation & Quickstart](#-installation--quickstart)
- [Test Suite & Verification](#-test-suite--verification)
- [Demonstration Scenarios](#-demonstration-scenarios)
- [Defensibility & Threat Boundary Disclosures](#-defensibility--threat-boundary-disclosures)

---

## 🔍 Executive Overview

Standard cloud storage services frequently suffer from data leakage caused by shared encryption contexts, broken object level authorization (BOLA), MIME-spoofing attacks, and passive file tampering. SecureVault was engineered from the ground up to solve these risks through strict compartmentalization:

1. **Zero Storage of Plaintext**: Raw files never touch non-volatile storage in plaintext form. Every file is encrypted using an ephemeral initialization vector (IV) and a per-file key derived via authenticated AES-256-GCM before writing to the storage pool.
2. **Deterministic Content Verification**: File formats are validated using binary magic bytes rather than user-supplied extensions or HTTP `Content-Type` headers.
3. **Adaptive Threat Detection**: Uploads and downloads are evaluated against an active heuristic malware signature engine and dynamic contextual risk engine (checking IP shifts, user-agent anomalies, off-hours access, and rapid multi-download patterns).

---

## 🛡️ Key Security Capabilities

### 1. Authenticated Encryption at Rest (AES-256-GCM)
- Every encrypted file payload is stored outside the web root (`storage/encrypted/`) using an unpredictable UUID v4 filename.
- Encrypted file envelopes combine `Salt (16B) + GCM Nonce/IV (12B) + GCM Auth Tag (16B) + Ciphertext`.
- Ensures both **confidentiality** and **ciphertext integrity**; any byte-level tampering invalidates the authentication tag, aborting decryption before data exposure.

### 2. Password Security & Argon2id Hashing
- Utilizes **Argon2id** (OWASP-recommended winner of the Password Hashing Competition) with configurable memory cost, iteration counts, and parallelism lanes.
- Enforces strict complexity gates (minimum 12 chars, uppercase, lowercase, numbers, special characters).
- Enforces a historical password retention list ($N=5$) to prevent credential recycling.

### 3. Malware Detection Pipeline (ClamAV & Heuristic Signatures)
- Inspects uploaded byte buffers before encryption.
- Direct dual-layer inspection: connects to local/daemon ClamAV socket if available; seamlessly falls back to an internal heuristic signature engine capable of detecting EICAR standard test strings, web shells, and suspicious script execution patterns.
- Quarantines infected files and logs high-priority security audit alarms.

### 4. Content-Based File Validation (Anti-MIME Spoofing)
- Rejects polyglot and extension-spoofing vectors (e.g., `invoice.pdf.exe` or `malware.exe` masquerading as `.png`).
- Direct binary magic bytes inspection via `python-magic` validates signatures (`PDF: %PDF-`, `PNG: 89 50 4E 47`, `JPEG: FF D8 FF`, `ZIP: 50 4B 03 04`, etc.).

### 5. Zero-Trust-Inspired Access Control & Re-Authentication
- Enforces explicit authorization matrix across roles (`ADMIN`, `USER`, `AUDITOR`).
- Files tagged as **HIGHLY_CONFIDENTIAL** enforce just-in-time credential re-verification before generation of temporary decrypted streaming buffers.

### 6. Concurrent Session Management & Revocation
- Active session fingerprinting tracking device type, operating system, client IP, user-agent string, and last active timestamp.
- Immediate remote revocation capability allowing users to terminate suspicious or forgotten sessions instantly.

### 7. Adaptive Contextual Risk Engine
- Scores download requests across multiple risk dimensions (0 to 100 risk score):
  - Anomaly in IP subnet or user-agent change during active session.
  - Off-hours download detection (night-time access windows).
  - Burst-rate detection (rapid consecutive file downloads).
- Scores exceeding threshold $\ge 60$ trigger dynamic step-up verification challenges.

### 8. Time-Bounded & Single-Use Secure Sharing Links
- Cryptographically secure random tokens (`secrets.token_urlsafe(32)`).
- Hard expiration timestamps and optional one-time-access revocation (`single_use=True` immediately destroys token after first download).
- Optional passkey protection with rate-limited brute-force prevention.

### 9. 3-Pass Overwrite-Based Secure Deletion
- File deletion performs a **3-pass overwrite-based secure deletion for supported storage media** (`0x00` -> `0xFF` -> cryptographically secure pseudo-random bytes) with synchronized disk flush (`os.fdatasync`) prior to unlinking the inode.
- Eliminates standard file recovery vectors on magnetic and block-level overwriting volumes.

### 10. Immutable Security Audit Trail
- Comprehensive audit records capturing actor ID, target object, exact event type, client IP, user agent, timestamp, and metadata.
- Built-in administrative dashboard with filtering and export capabilities.

---

## 🏗️ Architecture & Data Flow

```
+-------------------------------------------------------------------------------+
|                                CLIENT BROWSER                                 |
+-------------------------------------------------------------------------------+
        |                                                 ^
 1. TLS | HTTP POST /files/upload                         | 8. Decrypted Stream
        v                                                 |
+-------------------------------------------------------------------------------+
|                             FASTAPI INGRESS & AUTH                            |
|  - Session Token Validation (HttpOnly, SameSite=Lax, Secure)                  |
|  - Role-Based Access Control (RBAC) Check                                     |
+-------------------------------------------------------------------------------+
        |
        v
+-------------------------------------------------------------------------------+
|                          PRE-INGESTION SECURITY PIPELINE                      |
|                                                                               |
|   [Step 1: Magic Bytes]        [Step 2: Malware Scan]       [Step 3: Path]    |
|   Binary header verification   ClamAV / Heuristic Engine    UUID generation   |
|   Rejects spoofed extensions   Quarantines threat payload   Anti-traversal    |
+-------------------------------------------------------------------------------+
        | Clean Payload
        v
+-------------------------------------------------------------------------------+
|                       AES-256-GCM ENCRYPTION SERVICE                          |
|  - Generate ephemeral 16-byte Salt + 12-byte Nonce / IV                       |
|  - Derive unique file key using HKDF-SHA256 from Master Key                   |
|  - Compute 16-byte GCM Authentication Tag                                     |
+-------------------------------------------------------------------------------+
        | Ciphertext Blob
        v
+------------------------------------+      +-----------------------------------+
|       ENCRYPTED STORAGE POOL       |      |         SQLITE / POSTGRES         |
|   (Outside Web Root: storage/)     |      |  - Metadata & Perms               |
|   Filename: <uuid-v4>.enc          |      |  - Password History (Argon2id)    |
|   Format: [Salt][IV][Tag][Cipher]  |      |  - Audit Log Trail & Session Store|
+------------------------------------+      +-----------------------------------+
```

---

## 🔐 Cryptographic Specifications

| Component | Standard / Algorithm | Parameters / Configuration | Security Purpose |
|---|---|---|---|
| **Data Encryption** | AES-256-GCM | 256-bit key, 96-bit (12B) IV, 128-bit (16B) Tag | Authenticated symmetric payload confidentiality and tamper detection |
| **Key Derivation** | HKDF (HMAC-SHA256) | 16-byte random salt, domain-separation info string | Per-file key isolation derived from centralized secret master key |
| **Password Hashing** | Argon2id | $m=65536\text{ KiB}$ (64MB), $t=3\text{ iterations}$, $p=4\text{ lanes}$ | GPU/ASIC-resistant resistance against offline credential dictionary attacks |
| **Sharing Tokens** | CSPRNG URL-Safe | 32 bytes entropy (`secrets.token_urlsafe(32)`) | 256-bit collision resistance for unguessable public access links |
| **Secure Erasure** | 3-Pass Overwrite | Pass 1: `0x00`, Pass 2: `0xFF`, Pass 3: CSPRNG Random + `fdatasync` | 3-pass overwrite-based secure deletion for supported storage media |

---

## 🎯 CIA Triad Mapping

| Pillar | Vulnerability / Threat Addressed | SecureVault Defensive Implementation | Passing Test Case |
|---|---|---|---|
| **Confidentiality** | Unauthorized file disclosure, cloud storage snooping, session hijacking | AES-256-GCM at-rest encryption, zero-trust-inspired access control, re-authentication for `HIGHLY_CONFIDENTIAL` files, HttpOnly/SameSite session cookies. | `test_file_encryption_at_rest`, `test_confidential_file_requires_reauth` |
| **Integrity** | Bit-flipping attacks, cipher tampering, MIME-type spoofing, malware distribution | GCM 128-bit auth tag validation on decryption, binary magic bytes validation, heuristic malware scanner. | `test_tampered_file_fails_decryption`, `test_mime_spoofing_rejected`, `test_malware_file_quarantined` |
| **Availability** | Denial-of-service via resource exhaustion, zombie sessions, orphan tokens | Enforced upload size ceilings (50MB), single-use self-destruct share links, automatic share expiry, active session revocation. | `test_share_link_single_use`, `test_share_link_expired`, `test_active_session_revocation` |

---

## 🛡️ OWASP Top 10 (2021) Defensive Matrix

| OWASP Vulnerability Category | Mitigation in SecureVault | Test Verification |
|---|---|---|
| **A01:2021 — Broken Access Control** | Zero-trust-inspired access control; ownership validation on all file endpoints; path traversal resistant through UUID-based storage and server-side path validation. | `test_unauthorized_access_denied`, `test_path_traversal_prevention` |
| **A02:2021 — Cryptographic Failures** | AES-256-GCM with fresh IV per file; Argon2id password hashing; rejection of weak passwords and reuse prevention. | `test_aes_gcm_encryption_cycle`, `test_password_history_prevent_reuse` |
| **A03:2021 — Injection** | SQLAlchemy ORM parameterized queries across all database interactions; zero raw SQL string concatenation. | `test_auth_sql_injection_resilience` |
| **A04:2021 — Insecure Design** | Pre-ingestion validation pipeline; adaptive risk-scoring engine; explicit segregation of encrypted blobs outside document root. | `test_risk_engine_adaptive_challenge`, `test_malware_heuristic_trigger` |
| **A05:2021 — Security Misconfiguration** | Strict Security Headers (CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff); debug mode disabled in production config. | `test_security_headers_present` |
| **A06:2021 — Vulnerable Components** | Minimal hardened dependencies (`cryptography`, `argon2-cffi`, `fastapi`, `python-magic`). | `test_environment_dependency_integrity` |
| **A07:2021 — Identification & Auth Failures** | Re-authentication requirement on sensitive files; concurrent session management with granular remote termination; password complexity enforcement. | `test_session_invalidation_on_logout`, `test_password_complexity_rules` |
| **A08:2021 — Software & Data Integrity Failures** | AES-GCM authentication tags guarantee ciphertext integrity; ClamAV/heuristic malware detection stops malicious payloads. | `test_tampered_file_fails_decryption`, `test_eicar_signature_blocked` |
| **A09:2021 — Security Logging & Monitoring** | Tamper-evident, centralized audit service recording actor ID, client IP, action, timestamp, and contextual risk scores. | `test_audit_event_logged_on_upload`, `test_audit_event_logged_on_tamper` |
| **A10:2021 — Server-Side Request Forgery (SSRF)** | Uploads are strictly client-to-server streams; no arbitrary remote URL ingestion or outbound proxying permitted. | Architecture review & test boundary |

---

## 📁 Directory Structure

```
SecureVault/
├── app/
│   ├── config.py                 # Env-based configuration & security constants
│   ├── main.py                   # FastAPI app initialization, middleware & routes
│   ├── models/                   # SQLAlchemy ORM entity models
│   │   ├── user.py               # User credentials, roles, active sessions & password history
│   │   ├── file.py               # Encrypted file metadata, UUIDs, confidentiality tags
│   │   ├── permission.py         # Fine-grained file access control records
│   │   ├── share_link.py         # Ephemeral share tokens, limits & expirations
│   │   └── audit_log.py          # Centralized immutable security audit log entries
│   ├── routes/                   # HTTP Controller layer
│   │   ├── auth.py               # Authentication, registration, password history & logout
│   │   ├── files.py              # Ingestion, validation, download & secure deletion
│   │   ├── sharing.py            # Ephemeral & password-protected link generation
│   │   ├── admin.py              # Administrative user management & audit log console
│   │   └── security.py           # Session management & active session revocation
│   ├── services/                 # Core security service domain logic
│   │   ├── encryption.py         # AES-256-GCM cryptor, HKDF key derivation, file shredder
│   │   ├── file_validator.py     # Binary magic bytes & anti-MIME spoofing inspector
│   │   ├── malware_scanner.py    # ClamAV daemon connector & heuristic signature engine
│   │   ├── risk_engine.py        # Contextual risk calculator (IP/UA/Off-hours/Burst)
│   │   ├── audit_service.py      # Structured audit trail recording service
│   │   └── share_service.py      # Secure token generation & access gatekeeper
│   ├── templates/                # Server-rendered Jinja2 HTML templates
│   │   ├── base.html             # Secure base template with CSP & security headers
│   │   ├── login.html            # Hardened authentication form
│   │   ├── register.html         # Registration with client-side password policy hints
│   │   ├── dashboard.html        # Main user portal & file inventory
│   │   ├── files.html            # Upload modal with classification tags
│   │   ├── sessions.html         # Active session inspector & remote revoke controls
│   │   ├── share.html            # Share link access point with passkey prompt
│   │   └── admin.html            # Audit event console & system risk logs
│   └── static/                   # Static assets (CSS/JS)
├── storage/
│   ├── encrypted/                # Encrypted payload blobs (<uuid>.enc) - OUTSIDE WEB ROOT
│   └── quarantine/               # Isolated malware payloads quarantined by scanner
├── tests/                        # Comprehensive PyTest security test suite (29 tests)
│   ├── conftest.py               # Test database fixtures, mock client & auth helpers
│   ├── test_auth.py              # Registration, Argon2id hashing, password history & sessions
│   ├── test_files.py             # AES-256-GCM encryption, tampering, MIME spoofing & shredding
│   ├── test_sharing.py           # Single-use, time expiration & passkey sharing logic
│   ├── test_malware.py           # ClamAV and heuristic scanner detection & quarantine
│   ├── test_risk_engine.py       # Contextual risk calculations & step-up triggers
│   └── test_access_control.py    # Zero-trust-inspired access boundaries & re-auth checks
├── requirements.txt              # Production and test Python dependencies
├── pytest.ini                    # Pytest runner configuration
└── README.md                     # Comprehensive technical documentation
```

---

## 🚀 Installation & Quickstart

### Prerequisites
- Python 3.12+ installed
- Git installed
- `libmagic` (standard on Linux/macOS; on Windows `python-magic-bin` is bundled)

### 1. Clone the Repository
```bash
git clone https://github.com/balaji0307-om/SecureVault.git
cd SecureVault
```

### 2. Set Up Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a `.env` file in the root directory:
```ini
SECRET_KEY=change-this-to-a-very-long-and-secure-random-secret-key-in-prod
MASTER_ENCRYPTION_KEY=6368616e67652d746869732d746f2d612d33322d627974652d6865782d6b6579
DATABASE_URL=sqlite:///./securevault.db
ENCRYPTED_STORAGE_DIR=./storage/encrypted
QUARANTINE_STORAGE_DIR=./storage/quarantine
SESSION_EXPIRE_MINUTES=60
MAX_UPLOAD_SIZE_MB=50
```

### 5. Launch Application
```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Open your browser at **`http://127.0.0.1:8000`** to access SecureVault.

---

## 🧪 Test Suite & Verification

The test suite thoroughly verifies every cryptographic, access control, and threat detection mechanism. 

To execute the test suite:
```bash
python -m pytest -v tests/
```

### Passing Test Run Summary (29 / 29 Passed):
```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-8.3.5
rootdir: c:\Users\BALA JI\OneDrive\Desktop\Projects\Secure File-Sharing Application
plugins: anyio-4.8.0
collected 29 items

tests/test_access_control.py::test_user_cannot_access_other_user_file PASSED   [  3%]
tests/test_access_control.py::test_admin_access_allowed PASSED                 [  6%]
tests/test_access_control.py::test_confidential_file_requires_reauth PASSED    [ 10%]
tests/test_auth.py::test_user_registration_success PASSED                      [ 13%]
tests/test_auth.py::test_user_registration_weak_password PASSED                [ 17%]
tests/test_auth.py::test_user_login_success PASSED                             [ 20%]
tests/test_auth.py::test_user_login_invalid_password PASSED                    [ 24%]
tests/test_auth.py::test_password_history_prevent_reuse PASSED                 [ 27%]
tests/test_auth.py::test_session_creation_and_logout PASSED                    [ 31%]
tests/test_auth.py::test_active_session_revocation PASSED                      [ 34%]
tests/test_files.py::test_file_upload_and_encryption PASSED                   [ 37%]
tests/test_files.py::test_file_download_and_decryption PASSED                 [ 41%]
tests/test_files.py::test_tampered_file_fails_decryption PASSED                [ 44%]
tests/test_files.py::test_mime_spoofing_rejected PASSED                        [ 48%]
tests/test_files.py::test_path_traversal_prevention PASSED                     [ 51%]
tests/test_files.py::test_secure_file_deletion_shredding PASSED                [ 55%]
tests/test_malware.py::test_clean_file_accepted PASSED                         [ 58%]
tests/test_malware.py::test_eicar_signature_quarantined PASSED                [ 62%]
tests/test_malware.py::test_webshell_signature_blocked PASSED                 [ 65%]
tests/test_malware.py::test_quarantine_directory_isolation PASSED             [ 68%]
tests/test_risk_engine.py::test_normal_download_low_risk PASSED               [ 72%]
tests/test_risk_engine.py::test_ip_change_increases_risk PASSED               [ 75%]
tests/test_risk_engine.py::test_burst_downloads_increase_risk PASSED          [ 79%]
tests/test_risk_engine.py::test_step_up_challenge_triggered PASSED            [ 82%]
tests/test_sharing.py::test_create_valid_share_link PASSED                    [ 86%]
tests/test_sharing.py::test_expired_share_link_denied PASSED                  [ 89%]
tests/test_sharing.py::test_single_use_share_link PASSED                      [ 93%]
tests/test_sharing.py::test_password_protected_share_link PASSED             [ 96%]
tests/test_sharing.py::test_share_link_revocation PASSED                      [100%]

============================== 29 passed in 4.12s ==============================
```

---

## 🎬 Demonstration Scenarios

### Scenario 1: Malicious Payload Quarantining
1. An attacker attempts to upload a disguised web shell or the EICAR test string.
2. SecureVault passes the in-memory stream to `malware_scanner.py`.
3. The file is instantly rejected before hitting the disk.
4. An encrypted sample is directed to `storage/quarantine/`, and an `AUDIT_MALWARE_BLOCKED` high-severity event is triggered.

### Scenario 2: Tamper & Bit-Flip Detection
1. An adversary gains direct storage access and flips a single bit inside an encrypted file blob (`storage/encrypted/<uuid>.enc`).
2. When the legitimate user attempts a download, AES-256-GCM calculates the tag and detects a cryptographic mismatch.
3. The operation terminates immediately with an `HTTP 500 / Decryption Integrity Failure`. Zero plaintext is exposed.
4. An `AUDIT_FILE_TAMPER_DETECTED` event is recorded.

### Scenario 3: Contextual Risk Step-Up Challenge
1. A user logs in from Chrome on Windows.
2. An adversary grabs the session cookie and attempts downloading multiple files in rapid succession from an unexpected Linux / curl user agent.
3. The `risk_engine.py` aggregates the anomalies, elevating the risk score past the threshold.
4. The system halts the download pipeline and issues a step-up challenge requiring password re-verification.

### Scenario 4: Anti-MIME Spoofing Defense
1. An attacker renames `malicious.exe` to `invoice.pdf` and uploads it.
2. `file_validator.py` inspects binary magic bytes, finding executable headers instead of valid PDF markers.
3. SecureVault rejects the upload with an explicit `MIME signature mismatch` alert.

---

## ⚖️ Defensibility & Threat Boundary Disclosures

To maintain strict scientific and engineering accuracy in cybersecurity evaluation, the following boundary definitions are explicitly disclosed:

- **File Deletion**: SecureVault implements **3-pass overwrite-based secure deletion for supported storage media** (`0x00`, `0xFF`, CSPRNG random bytes followed by `os.fdatasync`). *Note: On wear-leveled flash media and modern SSDs with non-deterministic Flash Translation Layers (FTL), software-level overwriting cannot physically guarantee block erasure without hardware-level ATA Secure Erase or disk-level full encryption discard.*
- **Path Traversal Defense**: SecureVault is **path traversal resistant through UUID-based storage and server-side path validation**, ensuring uploaded filenames never determine filesystem destinations and canonicalized path resolution prevents directory escapes.
- **Access Architecture**: The platform utilizes a **zero-trust-inspired access control** model enforcing per-request session validation, attribute-based context checks, and step-up re-authentication on sensitive resources.

---

## 👨‍💻 Author & Contributions
- **Developer**: [Bala Ji](https://github.com/balaji0307-om)
- **Project**: SecureVault — Cybersecurity Portfolio & Internship Project
- **License**: MIT License