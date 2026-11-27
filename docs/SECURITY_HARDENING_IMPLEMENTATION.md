# CRIME404 security and integration handoff

## Changes in this patch

1. Removed the unsafe practice of writing a generated Flask secret into a plaintext `.env`; a private `instance/flask_secret.key` is created instead when no environment secret is supplied.
2. Added `.gitignore` and `.env.example`. The old `.env`, database files, keyring, evidence, backups and logs must not be distributed.
3. Integrated Argon2id password hashing with transparent verification/upgrade of legacy Werkzeug hashes, password policy checks, login throttling, TOTP MFA and one-time recovery codes.
4. Added database-backed idle-expiring sessions and logout-all revocation.
5. Removed self-service role changes. Case operations now call the RBAC helper, with organization checks and explicit case memberships.
6. Connected upload to content validation and AES-256-GCM encrypted evidence storage. SHA-256 is computed over original plaintext and verified after authenticated decryption.
7. Evidence removal/reset now retires an artifact from active analysis instead of deleting its original. Case deletion archives cases containing evidence.
8. Corrected the face-service API integration. Enrollment requires 3–8 camera samples; only an encrypted numeric template is stored. Fake descriptor fallbacks were removed.
9. Corrected WebAuthn option/verification handling and added server-side challenge validation. Registration fails closed when the WebAuthn dependency is missing.
10. Connected encrypted backups to the database, encrypted evidence originals and the keyring. Restore is staged and hash-verified; it does not automatically overwrite the live database.
11. Added a local SHA-256 hash-chained security event file and a verification endpoint. For strong tamper evidence, export/anchor the chain to an independently controlled log server; a local file alone cannot prevent an administrator from rewriting the entire chain.
12. Updated the investigation engine to ignore retired artifacts and to label hypotheses as heuristic working hypotheses rather than facts or calibrated probabilities.

## Setup

- Use Python 3.11 or 3.12 in a virtual environment.
- Install `pip install -r requirements.txt`.
- Optional face matching: install `pip install -r requirements-biometric.txt` only if the host can build/install `dlib` and `face-recognition`.
- Copy `.env.example` to `.env`; set a new random `SECRET_KEY`, mail settings, and the exact WebAuthn origin/RP ID. Never commit `.env`.
- Set `CRIME404_COOKIE_SECURE=1` and `CRIME404_FORCE_HTTPS=1` only behind correctly configured HTTPS in production.
- Keep `keys_isolated/` and `instance/` private and backed up. Losing the keyring makes encrypted evidence and backups unrecoverable.
- Rotate every credential that was present in an earlier shared `.env` file.

## Important limitations

- Face matching is a demo-grade 1:1 comparison, not liveness detection and not proof of identity. Do not use it as the sole control for consequential actions.
- WebAuthn uses the platform authenticator's user-verification policy. The operating system may use fingerprint, face, device PIN or another supported method; this does not guarantee fingerprint-only authentication.
- The face library is optional and may not install on every Windows/macOS environment. When unavailable, the API reports that it is unavailable and does not fake a match.
- Login throttling is process-memory based; a production multi-worker deployment should move throttling to a shared store such as Redis.
- The local audit hash chain detects modifications to individual entries but is not immutable against a privileged operator who can rewrite the whole file. Ship it to a separate log service for stronger guarantees.
- Backup restore is deliberately staged for inspection. An authorized operator must perform and validate the operational restore procedure.
- Flask integration tests and WebAuthn tests must be run in the project's target virtual environment after dependencies are installed. This review environment did not have Flask or WebAuthn installed and could not download packages.
- The first account created in a fresh database is bootstrapped as `lead_investigator`; subsequent registrations default to `investigator`. For production, control first-account provisioning and organization membership rather than exposing open registration.
- If `CRIME404_MASTER_KEY` is used instead of the local keyring file, preserve that environment secret in an independent secrets manager; it cannot be reconstructed from the project files.
