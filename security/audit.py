"""
CRIME404 Tamper-Evident Audit Logging & Security Alerting (Checklist Section 6)
- Hash-chained AuditLog records (SHA-256 chain linking prev_hash -> entry_hash).
- Automatic redaction of secrets (passwords, tokens, MFA codes, keys).
- Separate append-only JSONL security log stream for external SIEM/centralized collection.
- Anomaly detection alerts on repeated failed logins or authorization violations.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


SENSITIVE_KEYS = {
    "password", "new_password", "password_hash", "token", "reset_token",
    "secret", "totp_secret", "mfa_code", "recovery_code", "authorization",
    "cookie", "session_token", "wrapped_dek", "master_key",
}


def redact_dict(data: Any) -> Any:
    """Recursively redacts sensitive fields before writing to audit logs."""
    if isinstance(data, dict):
        out = {}
        for k, v in data.items():
            if str(k).lower() in SENSITIVE_KEYS:
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_dict(v)
        return out
    if isinstance(data, list):
        return [redact_dict(item) for item in data]
    return data


def compute_audit_entry_hash(
    prev_hash: str,
    timestamp_utc: str,
    org_id: int,
    user_id: Optional[int],
    username: str,
    action: str,
    target_type: str,
    target_id: str,
    outcome: str,
    reason: str,
    details_json: str,
) -> str:
    payload = "|".join([
        prev_hash or ("0" * 64),
        timestamp_utc,
        str(org_id or 0),
        str(user_id if user_id is not None else "anon"),
        username or "system",
        action,
        target_type or "",
        str(target_id or ""),
        outcome,
        reason or "",
        details_json or "{}",
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_security_jsonl(log_dir: str, entry: Dict[str, Any]) -> None:
    """Appends an immutable JSON-lines security record to logs/security_audit.jsonl."""
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "security_audit.jsonl")
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    try:
        os.chmod(log_path, 0o600)
    except OSError:
        pass


def verify_audit_chain(audit_rows: List[Any]) -> Tuple[bool, Optional[int], str]:
    """
    Verifies cryptographic hash chain across ordered AuditLog rows.
    Returns (is_valid, first_broken_id, message).
    """
    expected_prev = "0" * 64
    for row in audit_rows:
        if row.prev_hash != expected_prev:
            return False, row.id, f"Chain break at audit ID {row.id}: prev_hash mismatch."
        recomputed = compute_audit_entry_hash(
            prev_hash=row.prev_hash,
            timestamp_utc=row.timestamp_utc,
            org_id=row.org_id or 0,
            user_id=row.user_id,
            username=row.username,
            action=row.action,
            target_type=row.target_type,
            target_id=row.target_id,
            outcome=row.outcome,
            reason=row.reason or "",
            details_json=row.details_json or "{}",
        )
        if recomputed != row.entry_hash:
            return False, row.id, f"Tampering detected at audit ID {row.id}: entry_hash mismatch."
        expected_prev = row.entry_hash
    return True, None, f"Verified {len(audit_rows)} tamper-evident audit record(s)."
