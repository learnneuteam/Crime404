# CRIME404 Enterprise Security, Architecture & Governance Documentation

## 1. Technical & Security Architecture
CRIME404 is structured into four isolated layers:
- **Web & API Layer (`app.py`, `templates/`, `static/`)**: Enforces transport security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, optional `FORCE_HTTPS` + HSTS), server-side session validation, RBAC/case-level authorization, and paginated APIs.
- **Security & Identity Layer (`security/`)**:
  - `auth.py`: Password strength & compromised-password screening, Argon2id hashing (with `scrypt` fallback in minimal environments and transparent legacy hash upgrade), RFC 6238 TOTP MFA + single-use SHA-256 recovery codes, sliding-window login throttling, short-lived single-use password reset tokens, and server-side session revocation.
  - `rbac.py`: Five least-privilege roles (`system_admin`, `lead_investigator`, `investigator`, `evidence_reviewer`, `read_only_auditor`), case-level membership (`CaseMembership`), multi-tenant `Organization` isolation, and self-privilege escalation prevention.
  - `crypto.py`: AES-256-GCM envelope encryption (`AESGCM`), isolated Key Encryption Key (KEK) storage (`keys_isolated/` or `CRIME404_MASTER_KEY` env var), and key rotation.
  - `audit.py`: Cryptographically hash-chained `AuditLog` (`prev_hash -> entry_hash`), automatic secret redaction, and append-only `logs_isolated/security_audit.jsonl` stream.
- **Forensic Vault & Worker Layer (`forensics/`)**:
  - `vault.py`: Extension allowlist, executable/archive magic-byte rejection, NUL-byte rejection, quarantine staging, AES-256-GCM encrypted immutable originals (`evidence_vault_storage/originals/`), isolated working copies (`working/`), and SHA-256 verification.
  - `worker.py`: Modular `ParserRegistry` with versioned parsers and bounded `BackgroundWorkerPool`.
- **Backup & Disaster Recovery Layer (`services/backup.py`)**:
  - WAL-safe SQLite online backup + encrypted evidence originals packaged into AES-256-GCM `.c404bak` bundles in `backups_isolated/` with post-restore SHA-256 verification.

## 2. Threat Model & Risk Register
| Threat | Implemented Mitigation |
|---|---|
| Stolen passwords | Argon2id hashing, compromised-password blocklist, TOTP MFA + recovery codes, session revocation |
| Unauthorised case access | Server-side RBAC, `CaseMembership` checks, multi-tenant `org_id` isolation, audit logging of denials |
| Intercepted communication | `FORCE_HTTPS` TLS enforcement, HSTS, `HttpOnly`/`SameSite=Lax`/`Secure` cookies |
| Stolen database or backup | AES-256-GCM envelope encryption at rest, isolated `keys_isolated/` KEK, encrypted `.c404bak` backups |
| Malicious uploaded files | Magic-byte PE/ELF/Mach-O/archive rejection, NUL-byte check, 10 MB limit, quarantine, non-executable storage |
| Insider misuse | Least privilege, re-authentication (`428`) for sensitive actions, dual-control second-reviewer approval, hash-chained audit logs |
| Accidental data loss | Immutable original preservation (exclusion instead of deletion), WAL-safe encrypted backups, verified restore |
| Software vulnerability | Parameterized SQLAlchemy queries, input length/type bounds, secret redaction, `requirements.txt` pinning |
| Service disruption | Login rate limiting, bounded upload sizes, SQLite WAL + `busy_timeout`, indexed queries & pagination |

## 3. Privacy & Data-Handling Policy
- **Data Minimization**: Collects only investigator username, email, organization, and forensic log artifacts required for the investigation. Passwords, tokens, MFA secrets, and DEKs are automatically redacted from audit logs.
- **Retention & Disposal**: Evidence artifacts track `lifecycle_state` (`Under Examination`, `Excluded (Original Preserved)`, `Retained`, `Disposed`) and `retention_until`. Original files are preserved even when excluded from active analysis.
- **Privacy Incident Response**: Any suspected unauthorized access or hash mismatch triggers an `AuditLog` entry, session revocation (`logout_all_devices`), and key rotation (`KeyManager.rotate_master_key`).

## 4. Evidence-Handling & Chain-of-Custody Procedures
1. Uploaded files are staged in `quarantine/`, validated for content/magic bytes, hashed with SHA-256, and encrypted with a unique 256-bit DEK into `originals/` (`0400` permissions).
2. Every `INGESTED`, `DOWNLOADED`, `VERIFIED`, and `EXCLUDED` event is recorded in `CustodyEvent` with actor, UTC timestamp, reason, storage reference, and SHA-256 verification status.
3. Sensitive exclusions require recent re-authentication and (for `investigator` role or when requested) a second authorized reviewer's approval (`SensitiveActionRequest`).

## 5. Disaster Recovery Objectives (RTO / RPO)
- **RPO (Recovery Point Objective)**: 15 minutes (on-demand encrypted backup before critical operations + scheduled backups).
- **RTO (Recovery Time Objective)**: 30 minutes via `restore_and_verify_backup()` with full SHA-256 manifest verification.

## 6. Standards Alignment & Known Limitations
- **Reference Frameworks**: Aligned with **OWASP ASVS 5.0**, **OWASP Top 10**, **NIST CSF 2.0**, **NIST SP 800-53**, **NIST SP 800-86**, **ISO/IEC 27001**, and **ISO/IEC 27037** (guidance frameworks; formal certification requires independent audit).
- **Known Limitations**:
  1. **Pre-Collection Authenticity**: A matching SHA-256 hash proves the evidence file has not changed *since ingestion into CRIME404*. It does **not** prove the file was authentic or truthful before collection.
  2. **Probabilistic / Plausibility Scores**: Hypothesis plausibility scores and severity indices are deterministic investigative aids based on heuristic rules, **not** objectively verified probabilities of guilt.
  3. **Production Deployment**: For high-concurrency multi-node horizontal scaling, replace SQLite with PostgreSQL and move `BackgroundWorkerPool` to Celery/Redis with external KMS (AWS KMS / HashiCorp Vault) and a reverse proxy (Nginx/TLS).
