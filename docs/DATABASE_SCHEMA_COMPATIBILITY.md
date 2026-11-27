# Crime404 database compatibility repair (V3)

This patch targets the existing `instance/crime404_users.db` schema included in the user's uploaded project. It does not drop tables, delete cases, or reset users.

## Root cause addressed

The ORM models in the prior patch did not match the existing production SQLite schema. The old database contains legacy required columns in `artifact`, `finding`, `hypothesis`, `evidence_gap`, and `reassessment_snapshot`, while the application queried newer column names. A case insert could commit and then fail while `build_case_state()` queried those mismatched tables, producing a misleading case-save error. Evidence inserts also omitted legacy required artifact columns.

The updated models map to the legacy production columns where appropriate and add only the missing newer fields with idempotent `ALTER TABLE` migrations. No evidence files or existing records are intentionally deleted.

## Face recognition

The existing face service performs real 1:1 face-embedding comparison using `face_recognition`/dlib. It is not liveness detection and must not be treated as sole proof of identity for high-risk decisions. The application fails closed when dependencies are unavailable; no fallback enrollment is introduced.

## WebAuthn

For local development, open the app at exactly `http://localhost:5000` and configure `WEBAUTHN_RP_ID=localhost` and `WEBAUTHN_ORIGIN=http://localhost:5000`. Non-localhost deployments require HTTPS and a matching RP ID/origin.

## Before applying

Back up the full project and database. Do not run `reset_database.py`. Keep `.env`, keys, evidence vault and backups private and unchanged.
