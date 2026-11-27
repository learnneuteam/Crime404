"""
CRIME404 - Intelligent Digital Forensic Investigation System
Enterprise Flask Backend with SQLite WAL, Chain of Custody, Forensic Reasoning Engine,
and Integrated Profile / WebAuthn Biometric & Backup APIs.
"""

import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, text, func
from sqlalchemy.engine import Engine
from werkzeug.utils import secure_filename
from security.auth import (hash_password, verify_password, validate_password_strength, LoginThrottle, generate_totp_secret, get_totp_uri, verify_totp, verify_and_consume_recovery_code)
from security.crypto import KeyManager, encrypt_text_field, decrypt_text_field, apply_security_headers
from security.rbac import check_user_case_permission, is_valid_role, can_modify_user_role, role_has_permission, ROLE_PERMISSIONS
from forensics.vault import EvidenceVault, validate_evidence_content
from services.backup import create_encrypted_backup, restore_and_verify_backup, prune_old_backups
from security import face_recognition_service as face_service


def load_local_env(filepath=".env"):
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_local_env()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# Render mounts persistent storage at /var/data. Locally, keep the existing
# project-relative layout unless CRIME404_DATA_DIR is explicitly configured.
DATA_DIR = os.path.abspath(os.environ.get("CRIME404_DATA_DIR", BASE_DIR))
INSTANCE_DIR = os.path.join(DATA_DIR, "instance")
VAULT_DIR = os.path.join(DATA_DIR, "evidence_vault_storage")
ORIGINALS_DIR = os.path.join(VAULT_DIR, "originals")
BACKUPS_DIR = os.path.join(DATA_DIR, "backups_isolated")
os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs(ORIGINALS_DIR, exist_ok=True)
os.makedirs(BACKUPS_DIR, exist_ok=True)

if not os.environ.get("SECRET_KEY"):
    secret_path = os.path.join(INSTANCE_DIR, "flask_secret.key")
    if os.path.exists(secret_path):
        with open(secret_path, "r", encoding="utf-8") as sf:
            os.environ["SECRET_KEY"] = sf.read().strip()
    else:
        generated_secret = secrets.token_hex(32)
        with open(secret_path, "w", encoding="utf-8") as sf:
            sf.write(generated_secret)
        try:
            os.chmod(secret_path, 0o600)
        except OSError:
            pass
        os.environ["SECRET_KEY"] = generated_secret

SESSION_IDLE_SECONDS = int(os.environ.get("CRIME404_SESSION_IDLE_SECONDS", "1800"))
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
# Keep SQLite, but place the database on persistent storage when deployed.
DATABASE_PATH = os.path.join(INSTANCE_DIR, "crime404_users.db")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///" + DATABASE_PATH.replace(os.sep, "/")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("CRIME404_COOKIE_SECURE", "1" if os.environ.get("CRIME404_FORCE_HTTPS") == "1" else "0") == "1"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=SESSION_IDLE_SECONDS)

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "")

db = SQLAlchemy(app)
mail = Mail(app)

def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token

app.jinja_env.globals["csrf_token"] = csrf_token


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


try:
    from security.webauthn import registration_options, verify_registration, authentication_options, verify_authentication, b64url_encode, b64url_decode
    WEBAUTHN_AVAILABLE = True
except Exception:
    WEBAUTHN_AVAILABLE = False

FACE_VERIFICATION_AVAILABLE = face_service.is_available()
try:
    import cv2
    import numpy as np
    FACE_DETECTION_AVAILABLE = True
except Exception:
    cv2 = None
    np = None
    FACE_DETECTION_AVAILABLE = False

KEY_MANAGER = KeyManager(key_store_dir=os.environ.get("CRIME404_KEY_STORE_DIR", os.path.join(DATA_DIR, "keys_isolated")))
EVIDENCE_VAULT = EvidenceVault(VAULT_DIR, KEY_MANAGER)
LOGIN_THROTTLE = LoginThrottle(max_attempts=5, window_seconds=300, lockout_seconds=900)


# -----------------------------------------------------------------------------
# Persistent SQLite Models (Preserves existing crime404_users.db schema)
# -----------------------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(40), default="Lead Investigator")
    org_id = db.Column(db.Integer, default=1)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_expires_at = db.Column(db.DateTime, nullable=True)
    webauthn_credentials_json = db.Column(db.Text, default="[]")
    face_template_hash = db.Column(db.String(256), nullable=True)
    face_template_enc = db.Column(db.Text, nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    totp_secret_enc = db.Column(db.Text, nullable=True)
    totp_pending_enc = db.Column(db.Text, nullable=True)
    recovery_codes_json = db.Column(db.Text, default="[]")
    is_active = db.Column(db.Boolean, default=True)
    cases = db.relationship("Case", backref="investigator", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = hash_password(password)

    def check_password(self, password):
        valid, needs_rehash = verify_password(self.password_hash, password)
        if valid and needs_rehash:
            self.password_hash = hash_password(password)
        return valid


class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_code = db.Column(db.String(32), unique=True, nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, default="")
    status = db.Column(db.String(40), default="Active")
    org_id = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    artifacts = db.relationship("Artifact", backref="case", lazy=True, cascade="all, delete-orphan")
    events = db.relationship("LogEvent", backref="case", lazy=True, cascade="all, delete-orphan")
    findings = db.relationship("Finding", backref="case", lazy=True, cascade="all, delete-orphan")
    hypotheses = db.relationship("Hypothesis", backref="case", lazy=True, cascade="all, delete-orphan")
    gaps = db.relationship("EvidenceGap", backref="case", lazy=True, cascade="all, delete-orphan")
    snapshots = db.relationship("ReassessmentSnapshot", backref="case", lazy=True, cascade="all, delete-orphan")
    activity_logs = db.relationship("ActivityLog", backref="case", lazy=True, cascade="all, delete-orphan")


class Artifact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    artifact_code = db.Column(db.String(32), nullable=False)
    name = db.Column(db.String(200), nullable=False, default="")
    log_type = db.Column(db.String(60), nullable=False)
    sha256_hash = db.Column(db.String(64), default="")
    file_size = db.Column("file_size_bytes", db.Integer, default=0)
    storage_path = db.Column("stored_path", db.String(300), default="")
    uploaded_by = db.Column(db.String(80), default="Investigator")
    records_count = db.Column(db.Integer, default=0)
    coverage_window = db.Column(db.String(120), default="N/A")
    status = db.Column(db.String(40), default="Verified")
    processing_history_json = db.Column(db.Text, default="[]")
    wrapped_dek = db.Column(db.Text, default="")
    key_version = db.Column(db.String(20), default="")
    is_encrypted = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    original_filename = db.Column(db.String(200), nullable=False, default="")
    retired_at = db.Column(db.String(40), nullable=True)
    uploaded_at = db.Column(db.String(40), nullable=False)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)

    @property
    def stored_path(self):
        return self.storage_path


class LogEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_dt = db.Column(db.DateTime, nullable=False)
    timestamp_display = db.Column(db.String(40), nullable=False)
    original_tz = db.Column(db.String(40), default="UTC")
    ips_csv = db.Column(db.String(255), default="")
    username_entity = db.Column(db.String(80), nullable=True)
    file_entity = db.Column(db.String(120), nullable=True)
    process_entity = db.Column(db.String(120), nullable=True)
    description = db.Column(db.Text, nullable=False)
    source_file = db.Column(db.String(200), nullable=False)
    artifact_code = db.Column(db.String(32), default="")
    investigator_note = db.Column(db.Text, default="")
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)


class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    finding_code = db.Column(db.String(24), nullable=False, default=lambda: "F-" + secrets.token_hex(5).upper())
    title = db.Column(db.String(200), nullable=False)
    confidence_tier = db.Column(db.String(40), default="Strong Evidence")
    traceable_reason = db.Column(db.Text, nullable=False, default="")
    supporting_events_json = db.Column(db.Text, default="[]")
    detail = db.Column(db.Text, nullable=False, default="")
    confidence_reason = db.Column(db.Text, default="")
    mitre_id = db.Column(db.String(32), default="T1078")
    source_refs_json = db.Column(db.Text, default="[]")
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)


class Hypothesis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scenario_code = db.Column(db.String(24), nullable=False, default=lambda: "H-" + secrets.token_hex(5).upper())
    title = db.Column(db.String(200), nullable=False)
    summary = db.Column("description", db.Text, nullable=False, default="")
    plausibility = db.Column("plausibility_score", db.Integer, default=50)
    mitre_id = db.Column(db.String(32), default="T1110")
    supporting_json = db.Column("supporting_evidence_json", db.Text, default="[]")
    contradicting_json = db.Column("contradicting_evidence_json", db.Text, default="[]")
    questions_json = db.Column("unresolved_questions_json", db.Text, default="[]")
    required_evidence_json = db.Column(db.Text, default="[]")
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)


class EvidenceGap(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gap_code = db.Column(db.String(24), nullable=False, default=lambda: "G-" + secrets.token_hex(5).upper())
    gap_type = db.Column(db.String(80), nullable=False)
    title = db.Column("window_display", db.String(100), nullable=False, default="Unspecified evidence gap")
    explanation = db.Column(db.Text, nullable=False)
    recommended_source = db.Column(db.String(160), default="")
    severity = db.Column(db.String(30), default="HIGH")
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)


class ReassessmentSnapshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trigger_artifact_code = db.Column(db.String(30), nullable=False, default="SYSTEM")
    trigger_action = db.Column("trigger_filename", db.String(200), nullable=False, default="Reassessment")
    before_json = db.Column(db.Text, nullable=False, default="{}")
    after_json = db.Column(db.Text, nullable=False, default="{}")
    summary_diff = db.Column("delta_summary_json", db.Text, nullable=False, default="")
    severity_before = db.Column(db.Integer, default=0)
    severity_after = db.Column(db.Integer, default=0)
    created_at = db.Column(db.String(40), nullable=False)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)


class LoginSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, default=False)


class CaseMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    role_override = db.Column(db.String(40), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    __table_args__ = (db.UniqueConstraint("case_id", "user_id", name="uq_case_member"),)


class TeamInviteLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    org_id = db.Column(db.Integer, nullable=False, default=1)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=True)
    assigned_role = db.Column(db.String(40), nullable=False, default="investigator")
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_by_username = db.Column(db.String(80), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    max_uses = db.Column(db.Integer, default=10)
    uses_count = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def run_safe_migrations():
    with app.app_context():
        db.create_all()
        alter_statements = [
            "ALTER TABLE user ADD COLUMN role VARCHAR(40) DEFAULT 'Lead Investigator'",
            "ALTER TABLE user ADD COLUMN org_id INTEGER DEFAULT 1",
            "ALTER TABLE user ADD COLUMN webauthn_credentials_json TEXT DEFAULT '[]'",
            "ALTER TABLE user ADD COLUMN face_template_hash VARCHAR(256)",
            "ALTER TABLE user ADD COLUMN face_template_enc TEXT",
            "ALTER TABLE user ADD COLUMN mfa_enabled BOOLEAN DEFAULT 0",
            "ALTER TABLE user ADD COLUMN totp_secret_enc TEXT",
            "ALTER TABLE user ADD COLUMN totp_pending_enc TEXT",
            "ALTER TABLE user ADD COLUMN recovery_codes_json TEXT DEFAULT '[]'",
            "ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1",
            "ALTER TABLE user ADD COLUMN reset_expires_at DATETIME",
            "ALTER TABLE case ADD COLUMN org_id INTEGER DEFAULT 1",
            "ALTER TABLE case ADD COLUMN description TEXT DEFAULT ''",
            "ALTER TABLE case ADD COLUMN status VARCHAR(40) DEFAULT 'Active'",
            "ALTER TABLE artifact ADD COLUMN name VARCHAR(200) DEFAULT ''",
            "ALTER TABLE artifact ADD COLUMN wrapped_dek TEXT DEFAULT ''",
            "ALTER TABLE artifact ADD COLUMN key_version VARCHAR(20) DEFAULT ''",
            "ALTER TABLE artifact ADD COLUMN retired_at VARCHAR(40)",
            "ALTER TABLE finding ADD COLUMN detail TEXT DEFAULT ''",
            "ALTER TABLE finding ADD COLUMN confidence_reason TEXT DEFAULT ''",
            "ALTER TABLE finding ADD COLUMN mitre_id VARCHAR(32) DEFAULT 'T1078'",
            "ALTER TABLE finding ADD COLUMN source_refs_json TEXT DEFAULT '[]'",
            "ALTER TABLE hypothesis ADD COLUMN mitre_id VARCHAR(32) DEFAULT 'T1110'",
            "ALTER TABLE evidence_gap ADD COLUMN severity VARCHAR(30) DEFAULT 'HIGH'",
            "ALTER TABLE reassessment_snapshot ADD COLUMN severity_before INTEGER DEFAULT 0",
            "ALTER TABLE reassessment_snapshot ADD COLUMN severity_after INTEGER DEFAULT 0",
            "ALTER TABLE log_event ADD COLUMN original_tz VARCHAR(40) DEFAULT 'UTC'",
            "ALTER TABLE log_event ADD COLUMN artifact_code VARCHAR(32) DEFAULT ''",
        ]
        for stmt in alter_statements:
            try:
                db.session.execute(text(stmt))
                db.session.commit()
            except Exception:
                db.session.rollback()
        for sql in (
            "UPDATE artifact SET name = COALESCE(NULLIF(name, ''), NULLIF(original_filename, ''), artifact_code)",
            "UPDATE artifact SET is_active = COALESCE(is_active, 1)",
            "UPDATE artifact SET is_encrypted = COALESCE(is_encrypted, 0)",
            "UPDATE finding SET detail = COALESCE(NULLIF(detail, ''), traceable_reason, title)",
            "UPDATE hypothesis SET mitre_id = COALESCE(NULLIF(mitre_id, ''), 'T1110')",
            "UPDATE evidence_gap SET severity = COALESCE(NULLIF(severity, ''), 'HIGH')",
        ):
            try:
                db.session.execute(text(sql))
                db.session.commit()
            except Exception:
                db.session.rollback()


run_safe_migrations()

ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json"}
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_RE = re.compile(r"(?:user|usr|account|uid|username)[=:\s]+[\"']?([a-zA-Z0-9_.-]+)[\"']?", re.IGNORECASE)
FILE_RE = re.compile(r"([a-zA-Z0-9_.-]+\.(?:sql|db|zip|tar|gz|csv|pdf|json|xlsx|bak))", re.IGNORECASE)
PROC_RE = re.compile(r"([a-zA-Z0-9_.-]+\.(?:exe|sh|ps1|bat|py|bin)|powershell|sudo|mimikatz|netcat|nc)", re.IGNORECASE)


def normalize_timestamp(ts_raw, fallback_date=None, last_dt=None):
    if ts_raw is None or str(ts_raw).strip() == "":
        return None, None, None
    if fallback_date is None:
        fallback_date = datetime.now(timezone.utc).replace(tzinfo=None)

    if isinstance(ts_raw, (int, float)) or (isinstance(ts_raw, str) and re.fullmatch(r"\d{10}(?:\d{3})?", ts_raw.strip())):
        try:
            numeric = float(ts_raw)
            if numeric > 10_000_000_000:
                numeric /= 1000.0
            dt_utc = datetime.fromtimestamp(numeric, tz=timezone.utc).replace(tzinfo=None)
            return dt_utc, dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC"), "Unix epoch UTC"
        except (ValueError, OverflowError, OSError):
            return None, None, None

    s = str(ts_raw).strip()
    iso_m = re.search(r"(\d{4}-\d{2}-\d{2})[T\s](\d{2}:\d{2})(?::(\d{2}))?(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?", s)
    if iso_m:
        date_p, hm_p, sec_p, tz_p = iso_m.groups()
        try:
            dt_naive = datetime.strptime(f"{date_p} {hm_p}:{sec_p or '00'}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None, None, None
        orig_tz = tz_p or "UTC"
        if tz_p and tz_p != "Z":
            sign = 1 if tz_p[0] == "+" else -1
            tz_clean = tz_p[1:].replace(":", "")
            offset = timezone(sign * timedelta(hours=int(tz_clean[:2]), minutes=int(tz_clean[2:4]) if len(tz_clean) >= 4 else 0))
            dt_utc = dt_naive.replace(tzinfo=offset).astimezone(timezone.utc).replace(tzinfo=None)
        else:
            dt_utc = dt_naive
        return dt_utc, dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC"), orig_tz

    date_only = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", s)
    if date_only:
        try:
            dt_utc = datetime.strptime(date_only.group(1), "%Y-%m-%d")
            return dt_utc, dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC"), "UTC; date-only record"
        except ValueError:
            pass

    t_m = re.search(r"\b(\d{2}:\d{2}:\d{2})\b", s)
    if t_m:
        try:
            t_obj = datetime.strptime(t_m.group(1), "%H:%M:%S").time()
            dt_utc = datetime.combine(fallback_date.date(), t_obj)
            if last_dt and dt_utc < last_dt and (last_dt - dt_utc).total_seconds() > 43200:
                dt_utc += timedelta(days=1)
            return dt_utc, dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC"), "UTC (inferred date)"
        except ValueError:
            pass

    return None, None, None


def extract_entities(text_val):
    ips = list(dict.fromkeys(IP_RE.findall(text_val)))
    u_m = USER_RE.search(text_val)
    f_m = FILE_RE.search(text_val)
    p_m = PROC_RE.search(text_val)
    return {
        "ips": ips,
        "user": u_m.group(1) if u_m else None,
        "file": f_m.group(1) if f_m else None,
        "process": p_m.group(1) if p_m else None,
    }


def parse_json_evidence(content_str, filename, artifact_code):
    parsed = []
    try:
        data = json.loads(content_str)
    except json.JSONDecodeError:
        return parse_text_evidence(content_str, filename, artifact_code)

    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get("events") or data.get("logs") or [data]
    else:
        return []
    last_dt = None
    for rec in records:
        if not isinstance(rec, dict):
            continue
        ts_val = rec.get("timestamp") or rec.get("time") or rec.get("datetime") or rec.get("@timestamp")
        dt_utc, disp_ts, orig_tz = normalize_timestamp(ts_val, last_dt=last_dt)
        if not dt_utc:
            continue
        last_dt = dt_utc
        raw_line = json.dumps(rec, ensure_ascii=False)
        ents = extract_entities(raw_line)
        ips = list(dict.fromkeys([x for x in [rec.get("src_ip"), rec.get("dst_ip"), rec.get("ip")] if x] + ents["ips"]))
        user_val = rec.get("user") or rec.get("username") or ents["user"]
        file_val = rec.get("file") or rec.get("filename") or ents["file"]
        proc_val = rec.get("process") or ents["process"]
        action = rec.get("action") or rec.get("message") or rec.get("event") or raw_line
        desc = f"{action}"
        if user_val and user_val not in desc:
            desc += f" (user={user_val})"
        if ips and ips[0] not in desc:
            desc += f" from {ips[0]}"
        parsed.append({
            "event_dt": dt_utc,
            "timestamp_display": disp_ts,
            "original_tz": orig_tz or "UTC",
            "ips": ips,
            "user": user_val,
            "file": file_val,
            "process": proc_val,
            "description": desc,
            "source": filename,
            "artifact_code": artifact_code,
        })
    return parsed


def parse_csv_evidence(content_str, filename, artifact_code):
    import csv
    import io

    parsed = []
    reader = csv.DictReader(io.StringIO(content_str))
    if not reader.fieldnames:
        return parse_text_evidence(content_str, filename, artifact_code)

    last_dt = None
    for row in reader:
        ts_val = row.get("timestamp") or row.get("time") or row.get("datetime") or next(iter(row.values()), "")
        dt_utc, disp_ts, orig_tz = normalize_timestamp(ts_val, last_dt=last_dt)
        if not dt_utc:
            continue
        last_dt = dt_utc
        joined = " ".join(f"{k}={v}" for k, v in row.items() if v)
        ents = extract_entities(joined)
        ips = list(dict.fromkeys([x for x in [row.get("src_ip"), row.get("dst_ip"), row.get("ip")] if x] + ents["ips"]))
        user_val = row.get("user") or row.get("username") or ents["user"]
        file_val = row.get("file") or row.get("filename") or ents["file"]
        proc_val = row.get("process") or ents["process"]
        action = row.get("action") or row.get("event") or row.get("message") or joined
        desc = f"{action}"
        if file_val and file_val not in desc:
            desc += f" on {file_val}"
        if len(ips) >= 2:
            desc += f" ({ips[0]} -> {ips[1]})"
        elif ips and ips[0] not in desc:
            desc += f" ({ips[0]})"
        parsed.append({
            "event_dt": dt_utc,
            "timestamp_display": disp_ts,
            "original_tz": orig_tz or "UTC",
            "ips": ips,
            "user": user_val,
            "file": file_val,
            "process": proc_val,
            "description": desc,
            "source": filename,
            "artifact_code": artifact_code,
        })
    return parsed


def parse_text_evidence(content_str, filename, artifact_code):
    parsed = []
    last_dt = None
    for line in content_str.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        dt_utc, disp_ts, orig_tz = normalize_timestamp(s, last_dt=last_dt)
        if not dt_utc:
            continue
        last_dt = dt_utc
        ents = extract_entities(s)
        desc = re.sub(r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s*", "", s)
        desc = re.sub(r"^\d{2}:\d{2}:\d{2}\s*", "", desc).strip(" -:|[]") or s
        parsed.append({
            "event_dt": dt_utc,
            "timestamp_display": disp_ts,
            "original_tz": orig_tz or "UTC",
            "ips": ents["ips"],
            "user": ents["user"],
            "file": ents["file"],
            "process": ents["process"],
            "description": desc,
            "source": filename,
            "artifact_code": artifact_code,
        })
    return parsed


def dispatch_structured_parser(content_str, filename, artifact_code):
    ext = os.path.splitext(filename)[1].lower()
    if ext == ".json":
        return parse_json_evidence(content_str, filename, artifact_code)
    if ext == ".csv":
        return parse_csv_evidence(content_str, filename, artifact_code)
    return parse_text_evidence(content_str, filename, artifact_code)


# -----------------------------------------------------------------------------
# Forensic Reasoning Engine (Gaps, Contradictions, Hypotheses & Reassessment)
# -----------------------------------------------------------------------------
def run_forensic_reasoning_engine(case, trigger_label=None):
    artifacts = Artifact.query.filter_by(case_id=case.id, retired_at=None).order_by(Artifact.id.asc()).all()
    active_codes = [a.artifact_code for a in artifacts]
    events = LogEvent.query.filter(LogEvent.case_id == case.id, LogEvent.artifact_code.in_(active_codes)).order_by(LogEvent.event_dt.asc(), LogEvent.id.asc()).all() if active_codes else []

    prev_severity = 0
    if case.snapshots:
        prev_severity = case.snapshots[-1].severity_after

    Finding.query.filter_by(case_id=case.id).delete()
    Hypothesis.query.filter_by(case_id=case.id).delete()
    EvidenceGap.query.filter_by(case_id=case.id).delete()

    if not events:
        db.session.commit()
        return

    failed_by_ip = {}
    session_closed_at = {}
    has_priv_esc = False
    has_exfil = False
    has_script = False
    contradictions = []
    gaps_created = []

    for i, ev in enumerate(events):
        desc_l = ev.description.lower()
        ips = [x for x in ev.ips_csv.split(",") if x]
        user = ev.username_entity

        if any(k in desc_l for k in ["fail", "denied", "invalid", "unauthorized"]):
            for ip in ips:
                failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1
            db.session.add(Finding(
                title="Repeated Authentication Failure",
                detail=f"[{ev.timestamp_display}] {ev.description} (Source: {ev.source_file})",
                confidence_tier="Strong Evidence",
                confidence_reason="Directly recorded in authentication telemetry.",
                mitre_id="T1110",
                source_refs_json=json.dumps([ev.source_file]),
                case_id=case.id,
            ))

        if any(k in desc_l for k in ["terminated", "closed", "logout", "logged out"]):
            if user:
                session_closed_at[user] = (ev.event_dt, ev.timestamp_display, ev.source_file)

        if user and user in session_closed_at:
            closed_dt, closed_ts, closed_src = session_closed_at[user]
            if ev.event_dt > closed_dt and not any(k in desc_l for k in ["terminated", "closed", "logout"]):
                contradictions.append((user, closed_ts, closed_src, ev.timestamp_display, ev.source_file, ev.description))

        if any(k in desc_l for k in ["sudo", "privilege", "root", "escalat"]):
            has_priv_esc = True
            db.session.add(Finding(
                title="Privilege Escalation Execution",
                detail=f"[{ev.timestamp_display}] {ev.description}",
                confidence_tier="Corroborated" if len(artifacts) > 1 else "Unconfirmed",
                confidence_reason="Elevated command execution observed in host telemetry.",
                mitre_id="T1548",
                source_refs_json=json.dumps([ev.source_file]),
                case_id=case.id,
            ))

        if ev.process_entity or any(k in desc_l for k in ["payload", "powershell", ".ps1", ".sh", ".exe"]):
            has_script = True

        if any(k in desc_l for k in ["outbound", "exfil", "transfer", "egress", "upload"]):
            has_exfil = True
            db.session.add(Finding(
                title="External Data Egress Detected",
                detail=f"[{ev.timestamp_display}] {ev.description}",
                confidence_tier="Strong Evidence",
                confidence_reason="Confirmed outbound network flow record.",
                mitre_id="T1041",
                source_refs_json=json.dumps([ev.source_file]),
                case_id=case.id,
            ))

        if i > 0:
            prev_ev = events[i - 1]
            gap_mins = (ev.event_dt - prev_ev.event_dt).total_seconds() / 60.0
            if gap_mins > 5.0:
                mins_int = int(round(gap_mins))
                g = EvidenceGap(
                    gap_type="Operational Blind Spot",
                    title=f"Unexplained {mins_int}-Minute Telemetry Gap",
                    explanation=f"No log activity recorded between {prev_ev.timestamp_display} ({prev_ev.source_file}) and {ev.timestamp_display} ({ev.source_file}).",
                    recommended_source="Firewall / Router NetFlow or EDR Process Logs",
                    severity="CRITICAL" if mins_int >= 15 else "HIGH",
                    case_id=case.id,
                )
                db.session.add(g)
                gaps_created.append(g)

    for user, closed_ts, closed_src, act_ts, act_src, act_desc in contradictions:
        g = EvidenceGap(
            gap_type="Cross-Source Contradiction",
            title=f"Post-Logout Activity Contradiction for '{user}'",
            explanation=f"{closed_src} shows '{user}' terminated session at {closed_ts}, but {act_src} records '{act_desc}' later at {act_ts}.",
            recommended_source="Token / Session Persistence & NTP Clock Sync Audit",
            severity="CRITICAL",
            case_id=case.id,
        )
        db.session.add(g)
        gaps_created.append(g)

    if len(artifacts) == 1 and not has_exfil:
        g = EvidenceGap(
            gap_type="Missing Expected Telemetry",
            title="Missing Network Egress / Firewall Telemetry",
            explanation="Host authentication events are present, but no outbound firewall or proxy logs have been ingested yet.",
            recommended_source="Firewall Egress CSV / Router Flow Logs",
            severity="HIGH",
            case_id=case.id,
        )
        db.session.add(g)
        gaps_created.append(g)

    ext_score = 20
    ext_supp = []
    ext_contra = []
    if any(v >= 2 for v in failed_by_ip.values()):
        ext_score += 25
        ext_supp.append("Multiple failed login attempts preceding successful session establishment.")
    if has_priv_esc or has_script:
        ext_score += 20
        ext_supp.append("Privilege escalation and suspicious script execution observed immediately post-login.")
    if has_exfil:
        ext_score += 20
        ext_supp.append("Outbound transfer of sensitive archive to external IP address.")
    if not ext_supp:
        ext_supp.append("Initial anomalous host activity observed in ingested artifacts.")
    if not has_exfil:
        ext_contra.append("No confirmed external exfiltration flow recorded yet.")

    db.session.add(Hypothesis(
        title="External Intrusion via Credential Compromise",
        plausibility=min(96, ext_score),
        mitre_id="T1110 / T1078",
        summary="Working hypothesis only: an external actor may have used compromised credentials. The score is a heuristic, not a probability or a finding of fact; validate every stage against the cited artifacts.",
        supporting_json=json.dumps(ext_supp),
        contradicting_json=json.dumps(ext_contra),
        questions_json=json.dumps(["Which external ASN owns the destination egress IP?", "Was MFA bypassed or absent on the target account?"]),
        required_evidence_json=json.dumps(["Firewall Egress Logs", "DHCP / VPN Session Lease Table"]),
        case_id=case.id,
    ))

    insider_score = 20
    insider_supp = []
    observed_users = sorted({ev.username_entity for ev in events if ev.username_entity})
    if observed_users:
        insider_score += 10
        insider_supp.append("Account identifiers appear in the supplied telemetry: " + ", ".join(observed_users[:8]) + ". This does not establish who controlled the account.")
    else:
        insider_supp.append("No account identifier was extracted from the currently ingested events.")
    if contradictions:
        insider_score += 15
    insider_contra = []
    if contradictions:
        insider_contra.append("Session termination log contradicts subsequent privileged execution, indicating token hijacking or clock skew.")
    if any(v >= 2 for v in failed_by_ip.values()):
        insider_contra.append("Prior failed password attempts are atypical of normal authorized insider access.")

    db.session.add(Hypothesis(
        title="Insider Misuse or Hijacked Internal Session",
        plausibility=insider_score,
        mitre_id="T1078.002 / T1563",
        summary="Alternative working hypothesis: activity may involve misuse of an authorized account or a hijacked session. Current records do not identify the human operator; corroborate with endpoint, VPN and identity-provider evidence.",
        supporting_json=json.dumps(insider_supp),
        contradicting_json=json.dumps(insider_contra),
        questions_json=json.dumps(["Does badge/VPN telemetry place the account owner on-site during the window?"]),
        required_evidence_json=json.dumps(["Endpoint EDR Process Tree", "VPN / MFA Token Logs"]),
        case_id=case.id,
    ))

    db.session.commit()

    new_state = build_case_state(case)
    new_sev = new_state["metrics"]["severity_score"]
    if trigger_label:
        snap = ReassessmentSnapshot(
            trigger_action=trigger_label,
            summary_diff=f"Severity shifted {prev_severity} -> {new_sev}; {len(new_state['structured_hypotheses'])} hypotheses evaluated; {len(gaps_created)} gap/contradiction alert(s) active.",
            severity_before=prev_severity,
            severity_after=new_sev,
            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            case_id=case.id,
        )
        db.session.add(snap)
        db.session.commit()


def get_or_create_active_case(user_id):
    if session.get("active_case_user_id") != int(user_id):
        session.pop("active_case_id", None)
        session["active_case_user_id"] = int(user_id)

    active_id = session.get("active_case_id")
    case = Case.query.filter_by(id=active_id, user_id=user_id).first() if active_id else None
    if not case and active_id:
        membership = CaseMembership.query.filter_by(
            case_id=active_id, user_id=user_id, is_active=True
        ).first()
        case = db.session.get(Case, active_id) if membership else None

    if not case:
        case = Case.query.filter_by(user_id=user_id).order_by(Case.id.asc()).first()
    if not case:
        membership = CaseMembership.query.filter_by(user_id=user_id, is_active=True).order_by(CaseMembership.id.asc()).first()
        case = db.session.get(Case, membership.case_id) if membership else None

    if case and not authorize_case(case, "case:read"):
        case = None

    if not case:
        user = db.session.get(User, user_id)
        if not user or not user.is_active:
            raise PermissionError("The signed-in account is unavailable.")
        code = f"#404-{secrets.token_hex(3).upper()}-{datetime.now().year}"
        case = Case(case_code=code, title="Primary Intrusion Investigation",
                    description="Default workspace initialized for multi-source forensic correlation.",
                    status="Active", user_id=user_id, org_id=(user.org_id or 1))
        db.session.add(case)
        db.session.flush()
        db.session.add(ActivityLog(message=f"Workspace {code} initialized.", case_id=case.id))
        db.session.commit()

    session["active_case_id"] = case.id
    session["active_case_user_id"] = int(user_id)
    return case


def build_case_state(case):
    artifacts = Artifact.query.filter_by(case_id=case.id).order_by(Artifact.id.asc()).all()
    active_codes = [a.artifact_code for a in artifacts if not a.retired_at]
    events = LogEvent.query.filter(LogEvent.case_id == case.id, LogEvent.artifact_code.in_(active_codes)).order_by(LogEvent.event_dt.asc(), LogEvent.id.asc()).all() if active_codes else []
    findings = Finding.query.filter_by(case_id=case.id).order_by(Finding.id.asc()).all()
    hypotheses = Hypothesis.query.filter_by(case_id=case.id).order_by(Hypothesis.plausibility.desc()).all()
    gaps = EvidenceGap.query.filter_by(case_id=case.id).order_by(EvidenceGap.id.asc()).all()
    snapshots = ReassessmentSnapshot.query.filter_by(case_id=case.id).order_by(ReassessmentSnapshot.id.desc()).all()
    logs = ActivityLog.query.filter_by(case_id=case.id).order_by(ActivityLog.id.asc()).all()

    nodes_map = {}
    links = []
    link_keys = set()

    def add_node(nid, label, ntype):
        if nid not in nodes_map:
            nodes_map[nid] = {"id": nid, "label": label, "type": ntype}

    def add_link(src, dst, rel_label, source_file):
        key = (src, dst, rel_label)
        if src != dst and key not in link_keys:
            link_keys.add(key)
            links.append({"source": src, "target": dst, "label": rel_label, "evidence": source_file})

    timeline = []
    for i, ev in enumerate(events):
        if i > 0:
            diff_m = (ev.event_dt - events[i - 1].event_dt).total_seconds() / 60.0
            if diff_m > 5.0:
                mins_i = int(round(diff_m))
                timeline.append({
                    "id": f"gap-{i}",
                    "db_id": None,
                    "timestamp": f"{events[i - 1].timestamp_display} -> {ev.timestamp_display}",
                    "title": f"UNEXPLAINED TELEMETRY GAP ({mins_i} mins)",
                    "description": f"Missing records between {events[i - 1].source_file} and {ev.source_file}.",
                    "type": "gap",
                    "confidence": "0% (Missing Record)",
                    "source": "Adaptive Gap Detector",
                    "note": "",
                })

        desc_l = ev.description.lower()
        is_hyp = any(k in desc_l for k in ["sudo", "privilege", "payload", "powershell", ".ps1", "anomal"])
        timeline.append({
            "id": f"ev-{ev.id}",
            "db_id": ev.id,
            "timestamp": ev.timestamp_display,
            "original_tz": ev.original_tz,
            "title": "Behavioral Alert / Escalation" if is_hyp else "Corroborated Log Event",
            "description": ev.description,
            "type": "hypothesis" if is_hyp else "fact",
            "confidence": "82% (Heuristic)" if is_hyp else "100% (Logged)",
            "source": ev.source_file,
            "note": ev.investigator_note or "",
        })

        ips = [x for x in ev.ips_csv.split(",") if x]
        ents = []
        for ip in ips:
            nid = f"ip_{ip}"
            add_node(nid, f"IP {ip}", "ip")
            ents.append(nid)
        if ev.username_entity:
            nid = f"usr_{ev.username_entity}"
            add_node(nid, ev.username_entity, "user")
            ents.append(nid)
        if ev.file_entity:
            nid = f"file_{ev.file_entity}"
            add_node(nid, ev.file_entity, "file")
            ents.append(nid)
        if ev.process_entity:
            nid = f"proc_{ev.process_entity}"
            add_node(nid, ev.process_entity, "process")
            ents.append(nid)

        rel = "EXFILTRATED" if "outbound" in desc_l or "transfer" in desc_l else "EXECUTED" if is_hyp else "CONNECTED"
        for a in range(len(ents)):
            for b in range(a + 1, len(ents)):
                add_link(ents[a], ents[b], rel, ev.source_file)

    breakdown = []
    sev_score = 0
    if any("Egress" in f.title for f in findings):
        breakdown.append({
            "factor": "External Data Exfiltration Indicator (MITRE T1041)",
            "points": 35,
            "reason": "Outbound transfer or egress activity was detected in ingested network/host logs.",
        })
        sev_score += 35
    if any("Privilege" in f.title for f in findings):
        breakdown.append({
            "factor": "Privilege Escalation / Suspicious Script (MITRE T1548)",
            "points": 25,
            "reason": "Elevated execution (sudo, root, or script payload) occurred during the investigation window.",
        })
        sev_score += 25
    if any("Authentication" in f.title for f in findings):
        breakdown.append({
            "factor": "Repeated Failed Authentication Probing (MITRE T1110)",
            "points": 15,
            "reason": "Multiple failed or unauthorized authentication attempts were logged.",
        })
        sev_score += 15
    if gaps:
        gap_pts = min(25, len(gaps) * 12)
        breakdown.append({
            "factor": f"{len(gaps)} Unresolved Gap / Contradiction Alert(s)",
            "points": gap_pts,
            "reason": "Temporal telemetry blind spots (>5 min gap) or cross-source timeline contradictions remain unresolved.",
        })
        sev_score += gap_pts

    sev_score = min(100, sev_score)
    sev_label = "CRITICAL" if sev_score >= 70 else "HIGH" if sev_score >= 45 else "MODERATE" if sev_score > 0 else "LOW"

    evidence_payload = []
    for a in artifacts:
        evidence_payload.append({
            "id": a.artifact_code,
            "artifact_code": a.artifact_code,
            "name": a.name,
            "type": a.log_type,
            "sha256": a.sha256_hash,
            "sha256_hash": a.sha256_hash,
            "file_size": a.file_size,
            "records": a.records_count,
            "coverage": a.coverage_window,
            "uploaded_by": a.uploaded_by,
            "ingested_by": a.uploaded_by,
            "timestamp": a.uploaded_at,
            "ingested_at": a.uploaded_at,
            "status": a.status,
            "retired": bool(a.retired_at),
            "processing_history": json.loads(a.processing_history_json or "[]"),
        })

    viewer = current_user()
    if not viewer or not authorize_case(case, "case:read"):
        raise PermissionError("Case access denied for the current account.")
    assigned_case_ids = [m.case_id for m in CaseMembership.query.filter_by(
        user_id=viewer.id, is_active=True
    ).all()]
    case_query = Case.query.filter(Case.org_id == (viewer.org_id or 1))
    if role_code(viewer) in ("system_admin", "lead_investigator"):
        all_cases = case_query.order_by(Case.id.asc()).all()
    elif assigned_case_ids:
        all_cases = case_query.filter(
            (Case.user_id == viewer.id) | (Case.id.in_(assigned_case_ids))
        ).order_by(Case.id.asc()).all()
    else:
        all_cases = case_query.filter_by(user_id=viewer.id).order_by(Case.id.asc()).all()

    return {
        "active_case": {
            "id": case.id,
            "case_code": case.case_code,
            "title": case.title,
            "description": case.description or "",
            "status": case.status or "Active",
        },
        "cases": [
            {
                "id": c.id,
                "case_code": c.case_code,
                "title": c.title,
                "description": c.description or "",
                "status": c.status or "Active",
                "artifact_count": Artifact.query.filter_by(case_id=c.id, retired_at=None).count(),
            }
            for c in all_cases
        ],
        "metrics": {
            "severity_score": sev_score,
            "severity_label": sev_label,
            "severity_breakdown": breakdown,
            "total_events": len(events),
            "unresolved_gaps": len(gaps),
            "severity_method": "Heuristic indicator score (0–100) derived from MITRE ATT&CK detections and unresolved timeline gaps.",
        },
        "evidence": evidence_payload,
        "custody": evidence_payload,
        "timeline": timeline,
        "facts": [t["description"] for t in timeline if t["type"] == "fact"],
        "hypotheses": [h.title for h in hypotheses],
        "structured_findings": [
            {
                "id": f.id,
                "title": f.title,
                "detail": f.detail,
                "confidence_tier": f.confidence_tier,
                "confidence_reason": f.confidence_reason,
                "mitre_id": f.mitre_id,
                "sources": json.loads(f.source_refs_json or "[]"),
            }
            for f in findings
        ],
        "structured_hypotheses": [
            {
                "id": h.id,
                "title": h.title,
                "plausibility": h.plausibility,
                "mitre_id": h.mitre_id,
                "summary": h.summary,
                "supporting": json.loads(h.supporting_json or "[]"),
                "contradicting": json.loads(h.contradicting_json or "[]"),
                "questions": json.loads(h.questions_json or "[]"),
                "required_evidence": json.loads(h.required_evidence_json or "[]"),
            }
            for h in hypotheses
        ],
        "structured_gaps": [
            {
                "id": g.id,
                "gap_type": g.gap_type,
                "title": g.title,
                "explanation": g.explanation,
                "recommended_source": g.recommended_source,
                "severity": g.severity,
            }
            for g in gaps
        ],
        "reassessments": [
            {
                "id": s.id,
                "trigger": s.trigger_action,
                "diff": s.summary_diff,
                "severity_before": s.severity_before,
                "severity_after": s.severity_after,
                "created_at": s.created_at,
            }
            for s in snapshots
        ],
        "graph": {"nodes": list(nodes_map.values()), "links": links},
        "activity_logs": [l.message for l in logs[-60:]],
    }


def role_code(user):
    raw = (getattr(user, "role", None) or "lead_investigator").strip().lower().replace(" ", "_")
    aliases = {
        "lead_investigator": "lead_investigator",
        "lead investigator": "lead_investigator",
        "investigator": "investigator",
        "system_admin": "system_admin",
        "evidence_reviewer": "evidence_reviewer",
        "read_only_auditor": "read_only_auditor",
    }
    return aliases.get(raw, "investigator")


def current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None


def authorize_case(case, permission):
    user = current_user()
    if not user or not case:
        return False
    membership = CaseMembership.query.filter_by(case_id=case.id, user_id=user.id, is_active=True).first()
    if getattr(case, "org_id", None) is None:
        case.org_id = user.org_id or 1
    if role_code(user) == "lead_investigator" and (user.org_id or 1) == (case.org_id or 1):
        if role_has_permission("lead_investigator", permission):
            return True
    proxy = type("RBACUser", (), {"id": user.id, "role": role_code(user), "org_id": user.org_id or 1, "is_active": bool(user.is_active)})()
    allowed, reason = check_user_case_permission(proxy, case, permission, membership)
    if not allowed:
        session["suspicious_activity_flag"] = True
        session["suspicious_reason"] = f"Unauthorized access attempt ({permission}) on case {case.case_code}"
        append_audit("SUSPICIOUS_ACCESS_ATTEMPT", "case", case.id, outcome="DENIED", details={"permission": permission, "reason": reason})
    return allowed


def require_face_action(action):
    """Consume a short-lived, action-bound face verification grant."""
    user = current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    grant = session.get("face_verified_action") or {}
    if grant.get("action") != action or float(grant.get("expires", 0)) < datetime.now(timezone.utc).timestamp():
        session.pop("face_verified_action", None)
        return jsonify({
            "error": "Live face verification is required before uploading or modifying evidence.",
            "face_verification_required": True,
            "face_enrolled": bool(user.face_template_enc),
            "action": action,
        }), 428
    session.pop("face_verified_action", None)
    return None


def require_suspicious_face_clear():
    """Forces live face verification if suspicious activity or illegal access was flagged."""
    if not session.get("suspicious_activity_flag"):
        return None
    user = current_user()
    if not user or not user.face_template_enc or not FACE_VERIFICATION_AVAILABLE:
        return None
    gate = require_face_action("suspicious_activity_challenge")
    if gate:
        resp, code = gate
        payload = resp.get_json()
        payload["error"] = f"Suspicious activity detected ({session.get('suspicious_reason', 'security alert')}). Live face verification is required to continue."
        return jsonify(payload), code
    session.pop("suspicious_activity_flag", None)
    session.pop("suspicious_reason", None)
    append_audit("SUSPICIOUS_ACTIVITY_CLEARED", "user", user.id)
    return None


def store_face_template(user, images):
    if not FACE_VERIFICATION_AVAILABLE:
        raise face_service.FaceServiceUnavailable("Face verification dependencies are unavailable. Install requirements-biometric.txt and restart Flask.")
    template = face_service.enrollment_template(images)
    import base64
    user.face_template_enc = encrypt_text_field(base64.b64encode(template).decode("ascii"), KEY_MANAGER)
    user.face_template_hash = None


def create_login_session(user):
    raw = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    db.session.add(LoginSession(token_hash=hashlib.sha256(raw.encode()).hexdigest(), user_id=user.id, created_at=now, last_seen=now, expires_at=now + timedelta(seconds=SESSION_IDLE_SECONDS)))
    db.session.commit()
    session.clear()
    session["user_id"] = user.id
    session["username"] = user.username
    session["sid"] = raw
    session["active_case_user_id"] = user.id


@app.before_request
def enforce_server_session():
    uid, sid = session.get("user_id"), session.get("sid")
    if not uid:
        return None
    if not sid:
        session.clear()
        return None
    row = LoginSession.query.filter_by(token_hash=hashlib.sha256(sid.encode()).hexdigest(), user_id=uid, revoked=False).first()
    now = datetime.utcnow()
    if not row or row.expires_at <= now:
        session.clear()
        return None
    row.last_seen = now
    row.expires_at = now + timedelta(seconds=SESSION_IDLE_SECONDS)
    db.session.commit()
    return None


@app.before_request
def enforce_csrf():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    supplied = request.headers.get("X-CSRF-Token") or (request.form.get("csrf_token") if request.form else None)
    expected = session.get("_csrf_token")
    if not supplied or not expected or not secrets.compare_digest(str(supplied), str(expected)):
        return jsonify({"error": "CSRF validation failed. Refresh the page and try again."}), 403
    return None


@app.after_request
def security_headers(response):
    response = apply_security_headers(response, force_https=os.environ.get("CRIME404_FORCE_HTTPS", "0") == "1")
    if session.get("user_id") or request.path.startswith("/api/") or request.path == "/":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers["Vary"] = "Cookie"
    return response


AUDIT_DIR = os.path.join(DATA_DIR, "logs_isolated")
AUDIT_FILE = os.path.join(AUDIT_DIR, "security_audit.jsonl")
os.makedirs(AUDIT_DIR, exist_ok=True)

_AUDIT_LOCK = __import__("threading").RLock()


def append_audit(action, target_type="system", target_id="", outcome="SUCCESS", details=None):
    """Append a redacted, hash-chained record."""
    from security.audit import redact_dict
    os.makedirs(AUDIT_DIR, exist_ok=True)
    user = current_user()
    with _AUDIT_LOCK:
        prev = "0" * 64
        if os.path.exists(AUDIT_FILE):
            with open(AUDIT_FILE, "rb") as af:
                af.seek(0, os.SEEK_END)
                pos = af.tell() - 1
                if pos >= 0:
                    af.seek(pos)
                    if af.read(1) == b"\n":
                        pos -= 1
                    while pos >= 0:
                        af.seek(pos)
                        if af.read(1) == b"\n":
                            break
                        pos -= 1
                    af.seek(pos + 1)
                    last = af.readline().decode("utf-8", "replace").strip()
                    if last:
                        try:
                            prev = json.loads(last).get("entry_hash", prev)
                        except json.JSONDecodeError:
                            raise RuntimeError("Audit log tail is malformed; refusing to append.")
        record = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "user_id": session.get("user_id"),
            "org_id": getattr(user, "org_id", 1) if user else 1,
            "username": session.get("username", "anonymous"),
            "action": str(action),
            "target_type": str(target_type),
            "target_id": str(target_id),
            "outcome": str(outcome),
            "details": redact_dict(details or {}),
            "prev_hash": prev,
        }
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
        record["entry_hash"] = hashlib.sha256((prev + canonical).encode("utf-8")).hexdigest()
        with open(AUDIT_FILE, "a", encoding="utf-8") as af:
            af.write(json.dumps(record, sort_keys=True) + "\n")
        try:
            os.chmod(AUDIT_FILE, 0o600)
        except OSError:
            pass


def verify_audit_file():
    expected = "0" * 64
    if not os.path.exists(AUDIT_FILE):
        return True, 0, "No audit records yet."
    with open(AUDIT_FILE, "r", encoding="utf-8") as af:
        lines = af.readlines()
    for index, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return False, index, "Malformed audit record."
        claimed = record.pop("entry_hash", None)
        if record.get("prev_hash") != expected:
            return False, index, "Audit chain predecessor mismatch."
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
        actual = hashlib.sha256((expected + canonical).encode("utf-8")).hexdigest()
        if not secrets.compare_digest(str(claimed or ""), actual):
            return False, index, "Audit record hash mismatch."
        expected = actual
    return True, len(lines), f"Verified {len(lines)} audit record(s)."


@app.route("/api/audit/verify", methods=["GET"])
def api_audit_verify():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    case = get_or_create_active_case(session["user_id"])
    if not authorize_case(case, "audit:verify"):
        return jsonify({"error": "Permission denied"}), 403
    ok, count, message = verify_audit_file()
    return jsonify({"verified": ok, "records": count, "message": message, "note": "SHA-256 hash chain verified across all recorded security events."})


@app.route("/api/audit/logs", methods=["GET"])
def api_audit_logs():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user = current_user()
    if not user or role_code(user) not in ("system_admin", "lead_investigator", "evidence_reviewer", "read_only_auditor"):
        return jsonify({"error": "Your role cannot view the audit stream."}), 403
    rows = []
    if os.path.exists(AUDIT_FILE):
        with open(AUDIT_FILE, "r", encoding="utf-8") as af:
            for line in af.readlines()[-100:]:
                try:
                    row = json.loads(line)
                    if row.get("org_id") == (user.org_id or 1):
                        rows.append({k: row.get(k) for k in ("timestamp_utc", "username", "action", "target_type", "target_id", "outcome", "entry_hash")})
                except json.JSONDecodeError:
                    rows.append({"action": "MALFORMED_AUDIT_RECORD", "outcome": "ERROR"})
    return jsonify({"logs": list(reversed(rows))})


@app.route("/api/org/users", methods=["GET"])
def api_org_users():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    actor = current_user()
    if not actor or role_code(actor) not in ("system_admin", "lead_investigator"):
        return jsonify({"error": "Only a lead investigator or system administrator can view organization members."}), 403
    users = User.query.filter_by(org_id=(actor.org_id or 1), is_active=True).order_by(User.username.asc()).all()
    return jsonify({
        "org_id": actor.org_id or 1,
        "can_edit_roles": role_code(actor) in ("system_admin", "lead_investigator"),
        "users": [{"id": u.id, "username": u.username, "email": u.email, "role": role_code(u)} for u in users],
    })


@app.route("/organization/invitations", methods=["GET"])
def organization_invitations_page():
    if "user_id" not in session:
        return redirect(url_for("login"))
    actor = current_user()
    if not actor or role_code(actor) not in ("system_admin", "lead_investigator"):
        flash("Only a Lead Investigator or System Administrator can manage team invitations.", "danger")
        return redirect(url_for("dashboard"))
    return render_template("org_invites.html")


@app.route("/api/org/invites", methods=["GET", "POST"])
def api_org_invites():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    actor = current_user()
    if not actor or role_code(actor) not in ("system_admin", "lead_investigator"):
        return jsonify({"error": "Only a lead investigator or system administrator can manage team invite links."}), 403
    org_id = actor.org_id or 1
    now = datetime.utcnow()

    if request.method == "GET":
        invites = TeamInviteLink.query.filter_by(org_id=org_id, is_active=True).order_by(TeamInviteLink.id.desc()).all()
        out = []
        for inv in invites:
            expired = inv.expires_at <= now or inv.uses_count >= inv.max_uses
            out.append({
                "id": inv.id,
                "token": inv.token,
                "invite_url": url_for("join_team_via_link", token=inv.token, _external=True),
                "assigned_role": inv.assigned_role,
                "created_by": inv.created_by_username,
                "uses_count": inv.uses_count,
                "max_uses": inv.max_uses,
                "expires_at": inv.expires_at.strftime("%Y-%m-%d %H:%M UTC"),
                "expired": expired,
            })
        return jsonify({"invites": out})

    data = request.get_json(silent=True) or {}
    assigned_role = (data.get("role") or "investigator").strip().lower()
    if assigned_role not in ("lead_investigator", "investigator", "evidence_reviewer", "read_only_auditor"):
        return jsonify({"error": "Invalid team role selected."}), 400
    hours = max(1, min(168, int(data.get("expires_hours") or 48)))
    max_uses = max(1, min(50, int(data.get("max_uses") or 10)))
    active_case = get_or_create_active_case(actor.id)
    token = secrets.token_urlsafe(24)
    inv = TeamInviteLink(
        token=token,
        org_id=org_id,
        case_id=active_case.id if active_case else None,
        assigned_role=assigned_role,
        created_by_id=actor.id,
        created_by_username=actor.username,
        expires_at=now + timedelta(hours=hours),
        max_uses=max_uses,
        is_active=True,
    )
    db.session.add(inv)
    db.session.commit()
    invite_url = url_for("join_team_via_link", token=token, _external=True)
    append_audit("ORG_INVITE_CREATED", "organization", org_id, details={"role": assigned_role, "max_uses": max_uses})
    return jsonify({
        "success": True,
        "invite": {
            "id": inv.id,
            "token": inv.token,
            "invite_url": invite_url,
            "assigned_role": inv.assigned_role,
            "created_by": inv.created_by_username,
            "uses_count": 0,
            "max_uses": inv.max_uses,
            "expires_at": inv.expires_at.strftime("%Y-%m-%d %H:%M UTC"),
            "expired": False,
        },
    })


@app.route("/api/org/invites/<int:invite_id>", methods=["DELETE"])
def api_revoke_org_invite(invite_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    actor = current_user()
    if not actor or role_code(actor) not in ("system_admin", "lead_investigator"):
        return jsonify({"error": "Permission denied."}), 403
    inv = TeamInviteLink.query.filter_by(id=invite_id, org_id=(actor.org_id or 1)).first()
    if not inv:
        return jsonify({"error": "Invite link not found."}), 404
    inv.is_active = False
    db.session.commit()
    append_audit("ORG_INVITE_REVOKED", "invite", invite_id)
    return jsonify({"success": True})


@app.route("/join/<token>", methods=["GET"])
def join_team_via_link(token):
    inv = TeamInviteLink.query.filter_by(token=token, is_active=True).first()
    if not inv or inv.expires_at <= datetime.utcnow() or inv.uses_count >= inv.max_uses:
        flash("This team invite link is invalid or has expired.", "danger")
        return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))

    if "user_id" not in session:
        session["pending_invite_token"] = token
        flash(f"Complete registration to join {inv.created_by_username}'s investigation team as {inv.assigned_role.replace('_', ' ')}.", "info")
        return redirect(url_for("signup"))

    user = current_user()
    if not user:
        return redirect(url_for("login"))
    _redeem_team_invite(user, inv)
    flash(f"Joined {inv.created_by_username}'s investigation team as {inv.assigned_role.replace('_', ' ')}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/api/org/invites/accept", methods=["POST"])
def api_accept_org_invite():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user = current_user()
    data = request.get_json(silent=True) or {}
    raw = (data.get("token") or "").strip()
    if "/join/" in raw:
        raw = raw.rsplit("/join/", 1)[-1].strip("/")
    inv = TeamInviteLink.query.filter_by(token=raw, is_active=True).first()
    if not inv or inv.expires_at <= datetime.utcnow() or inv.uses_count >= inv.max_uses:
        return jsonify({"error": "Invalid or expired team invite link/token."}), 400
    _redeem_team_invite(user, inv)
    return jsonify({"success": True, "role": role_code(user), "org_id": user.org_id})


def _redeem_team_invite(user, inv):
    user.org_id = inv.org_id
    if inv.assigned_role in ("lead_investigator", "investigator", "evidence_reviewer", "read_only_auditor"):
        user.role = inv.assigned_role
    if inv.case_id:
        case = db.session.get(Case, inv.case_id)
        if case and case.user_id != user.id:
            existing = CaseMembership.query.filter_by(case_id=case.id, user_id=user.id).first()
            if existing:
                existing.is_active = True
                existing.role_override = inv.assigned_role
            else:
                db.session.add(CaseMembership(case_id=case.id, user_id=user.id, role_override=inv.assigned_role, is_active=True))
            session["active_case_id"] = case.id
            session["active_case_user_id"] = user.id
    inv.uses_count = (inv.uses_count or 0) + 1
    if inv.uses_count >= inv.max_uses:
        inv.is_active = False
    db.session.commit()
    append_audit("ORG_INVITE_ACCEPTED", "user", user.id, details={"org_id": inv.org_id, "role": inv.assigned_role, "invited_by": inv.created_by_username})


@app.route("/api/logout-all", methods=["POST"])
def api_logout_all():
    gate = require_face_action("logout_all")
    if gate:
        return gate
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    LoginSession.query.filter_by(user_id=session["user_id"]).update({"revoked": True})
    db.session.commit()
    session.clear()
    return jsonify({"success": True})


# -----------------------------------------------------------------------------
# Authentication Routes
# -----------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ident = (request.form.get("username") or "").strip()
        pw = request.form.get("password") or ""
        ip = request.remote_addr or "unknown"
        blocked, wait_s = LOGIN_THROTTLE.is_blocked(ident, ip)
        if blocked:
            append_audit("LOGIN_THROTTLED", "account", ident[:80], outcome="BLOCKED", details={"ip": ip, "retry_after_seconds": int(wait_s)})
            flash(f"Too many attempts. Try again in about {max(1, wait_s // 60)} minute(s).", "danger")
            return render_template("login.html", face_supported=FACE_VERIFICATION_AVAILABLE)
        user = User.query.filter((User.username == ident) | (User.email == ident)).first()
        if user and user.is_active and user.check_password(pw):
            if user.mfa_enabled:
                code = request.form.get("mfa_code", "")
                try:
                    secret = decrypt_text_field(user.totp_secret_enc or "", KEY_MANAGER)
                except Exception:
                    secret = ""
                totp_ok = verify_totp(secret, code)
                recovery_ok = False
                if not totp_ok:
                    recovery_ok, remaining = verify_and_consume_recovery_code(code, json.loads(user.recovery_codes_json or "[]"))
                    if recovery_ok:
                        user.recovery_codes_json = json.dumps(remaining)
                        db.session.commit()
                if not (totp_ok or recovery_ok):
                    LOGIN_THROTTLE.record_failure(ident, ip)
                    flash("A valid authenticator or unused recovery code is required.", "danger")
                    return render_template("login.html", face_supported=FACE_VERIFICATION_AVAILABLE)
            if user.face_template_enc:
                if not FACE_VERIFICATION_AVAILABLE:
                    flash("Face verification is temporarily unavailable. Sign-in is blocked until the biometric service is restored.", "danger")
                    return render_template("login.html", face_required=True, prefill_username=ident, face_supported=False), 503
                face_image = (request.form.get("face_image") or "").strip()
                if not face_image:
                    flash("Live face verification is required to sign in to this account.", "warning")
                    return render_template("login.html", face_required=True, prefill_username=ident, face_supported=FACE_VERIFICATION_AVAILABLE), 401
                try:
                    import base64
                    template_b64 = decrypt_text_field(user.face_template_enc, KEY_MANAGER)
                    matched, dist = face_service.verify_template(face_image, base64.b64decode(template_b64))
                except (ValueError, face_service.FaceServiceUnavailable) as exc:
                    LOGIN_THROTTLE.record_failure(ident, ip)
                    append_audit("LOGIN_FACE_FAILED", "user", user.id, outcome="FAILURE", details={"ip": ip, "error": str(exc)})
                    flash(str(exc), "danger")
                    return render_template("login.html", face_required=True, prefill_username=ident, face_supported=FACE_VERIFICATION_AVAILABLE), 401
                if not matched:
                    LOGIN_THROTTLE.record_failure(ident, ip)
                    append_audit("LOGIN_FACE_FAILED", "user", user.id, outcome="FAILURE", details={"ip": ip, "distance": round(float(dist), 4)})
                    flash("Face verification failed — live face did not match enrolled investigator.", "danger")
                    return render_template("login.html", face_required=True, prefill_username=ident, face_supported=FACE_VERIFICATION_AVAILABLE), 401
                append_audit("LOGIN_FACE_VERIFIED", "user", user.id, details={"ip": ip, "distance": round(float(dist), 4)})

            prev_ip = None
            if os.path.exists(AUDIT_FILE):
                try:
                    with open(AUDIT_FILE, "r", encoding="utf-8") as af:
                        for raw_line in af:
                            raw_line = raw_line.strip()
                            if not raw_line:
                                continue
                            rec = json.loads(raw_line)
                            if rec.get("action") == "LOGIN_SUCCESS" and str(rec.get("target_id")) == str(user.id):
                                prev_ip = (rec.get("details") or {}).get("ip")
                except Exception:
                    prev_ip = None
            is_new_ip = bool(prev_ip and prev_ip != ip)

            LOGIN_THROTTLE.record_success(ident, ip)
            pending_tok = session.pop("pending_invite_token", None)
            append_audit("LOGIN_SUCCESS", "user", user.id, details={"ip": ip, "suspicious_new_ip": is_new_ip})
            create_login_session(user)
            if is_new_ip:
                session["suspicious_activity_flag"] = True
                session["suspicious_reason"] = f"New login IP detected ({ip})"
                append_audit("SUSPICIOUS_LOGIN_DETECTED", "user", user.id, details={"ip": ip, "previous_ip": prev_ip})
            if pending_tok:
                inv = TeamInviteLink.query.filter_by(token=pending_tok, is_active=True).first()
                if inv and inv.expires_at > datetime.utcnow() and inv.uses_count < inv.max_uses:
                    _redeem_team_invite(user, inv)
            get_or_create_active_case(user.id)
            return redirect(url_for("dashboard"))
        LOGIN_THROTTLE.record_failure(ident, ip)
        append_audit("LOGIN_FAILURE", "account", ident[:80], outcome="FAILURE", details={"ip": ip})
        flash("Invalid username/email or password", "danger")
    return render_template("login.html", face_supported=FACE_VERIFICATION_AVAILABLE)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        requested_role = (request.form.get("role") or "investigator").strip().lower()
        consent = request.form.get("biometric_consent") == "yes"
        try:
            images = json.loads(request.form.get("face_samples") or "[]")
        except (TypeError, json.JSONDecodeError):
            images = []

        valid, reason = validate_password_strength(password, username=username, email=email)
        if not username or not email or not valid:
            flash(reason if not valid else "Username and email are required.", "warning")
            return redirect(url_for("signup"))
        if requested_role not in ("lead_investigator", "investigator", "evidence_reviewer", "read_only_auditor"):
            flash("Please select a valid registration role. System Administrator access cannot be self-assigned.", "warning")
            return redirect(url_for("signup"))
        if not consent:
            flash("Please provide consent to enroll your face for biometric sign-in.", "warning")
            return redirect(url_for("signup"))
        if len(images) < 3:
            flash("Please capture at least three face samples before creating your account.", "warning")
            return redirect(url_for("signup"))
        if not FACE_VERIFICATION_AVAILABLE:
            flash("Face verification is unavailable. Install requirements-biometric.txt before registering.", "danger")
            return redirect(url_for("signup"))
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash("Username or email already exists.", "warning")
            return redirect(url_for("signup"))

        initial_account = User.query.count() == 0
        pending_tok = session.get("pending_invite_token")
        invite = None
        if pending_tok:
            invite = TeamInviteLink.query.filter_by(token=pending_tok, is_active=True).first()
            if not invite or invite.expires_at <= datetime.utcnow() or invite.uses_count >= invite.max_uses:
                session.pop("pending_invite_token", None)
                flash("Your team invitation is invalid or expired. Please request a new link.", "danger")
                return redirect(url_for("signup"))

        # The first account bootstraps the organisation as Lead Investigator.
        # After bootstrap, public registration honours the selected role, including
        # Lead Investigator. A valid team invitation takes precedence so invitees
        # join the inviter's organisation with the role encoded in that invitation.
        if initial_account:
            assigned_role, assigned_org = "lead_investigator", 1
        elif invite:
            assigned_role, assigned_org = invite.assigned_role, invite.org_id
        else:
            assigned_role, assigned_org = requested_role, 1

        u = User(username=username, email=email, role=assigned_role, org_id=assigned_org)
        u.set_password(password)
        try:
            store_face_template(u, images)
            db.session.add(u)
            db.session.commit()
            if invite:
                _redeem_team_invite(u, invite)
                session.pop("pending_invite_token", None)
        except (ValueError, face_service.FaceServiceUnavailable) as exc:
            db.session.rollback()
            flash(str(exc), "danger")
            return redirect(url_for("signup"))
        except Exception:
            db.session.rollback()
            app.logger.exception("Account registration failed")
            flash("Account registration failed. Please retry.", "danger")
            return redirect(url_for("signup"))

        append_audit("ACCOUNT_CREATED", "user", u.id, details={"initial_lead": initial_account, "assigned_role": assigned_role, "face_enrolled": True})
        flash(f"Account created as {assigned_role.replace('_', ' ').title()} with encrypted face enrollment. Please log in.", "success")
        return redirect(url_for("login"))

    pending_tok = session.get("pending_invite_token")
    pending_invite = None
    if pending_tok:
        candidate = TeamInviteLink.query.filter_by(token=pending_tok, is_active=True).first()
        if candidate and candidate.expires_at > datetime.utcnow() and candidate.uses_count < candidate.max_uses:
            pending_invite = candidate
        else:
            session.pop("pending_invite_token", None)
    return render_template(
        "signup.html",
        face_supported=FACE_VERIFICATION_AVAILABLE,
        prefill_role=(pending_invite.assigned_role if pending_invite else None),
        invited_role=(pending_invite.assigned_role if pending_invite else None),
        invited_by=(pending_invite.created_by_username if pending_invite else None),
    )


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        user = User.query.filter_by(email=email).first()
        if user:
            if not app.config["MAIL_USERNAME"] or not app.config["MAIL_PASSWORD"]:
                flash("SMTP not configured yet. Set MAIL_USERNAME and MAIL_PASSWORD in .env.", "warning")
                return redirect(url_for("forgot_password"))
            token = secrets.token_urlsafe(32)
            user.reset_token = hashlib.sha256(token.encode()).hexdigest()
            user.reset_expires_at = datetime.utcnow() + timedelta(minutes=15)
            db.session.commit()
            reset_url = url_for("reset_password", token=token, _external=True)
            msg = Message("CRIME404 - Password Reset", sender=app.config["MAIL_USERNAME"], recipients=[email])
            msg.body = f"Hi {user.username},\n\nReset your CRIME404 password here:\n{reset_url}"
            try:
                mail.send(msg)
                flash("Password reset link sent to your Gmail!", "info")
            except Exception:
                app.logger.exception("Password reset email delivery failed")
        flash("If the account exists and email is configured, a reset link will be sent.", "info")
    return render_template("forgot.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    user = User.query.filter_by(reset_token=token_hash).first()
    if not user or not user.reset_expires_at or user.reset_expires_at <= datetime.utcnow():
        flash("Invalid or expired reset token", "danger")
        return redirect(url_for("login"))
    if request.method == "POST":
        new_password = request.form.get("password") or ""
        valid, reason = validate_password_strength(new_password, username=user.username, email=user.email)
        if not valid:
            flash(reason, "danger")
            return render_template("reset.html", token=token)
        user.set_password(new_password)
        user.reset_token = None
        user.reset_expires_at = None
        LoginSession.query.filter_by(user_id=user.id).update({"revoked": True})
        db.session.commit()
        append_audit("PASSWORD_RESET_COMPLETED", "user", user.id, details={"all_sessions_revoked": True})
        flash("Password updated! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("reset.html", token=token)


@app.route("/logout", methods=["POST"])
def logout():
    sid = session.get("sid")
    if sid:
        LoginSession.query.filter_by(token_hash=hashlib.sha256(sid.encode()).hexdigest()).update({"revoked": True})
        db.session.commit()
    session.clear()
    return redirect(url_for("login"))


# -----------------------------------------------------------------------------
# Main Workspace & Case Management APIs
# -----------------------------------------------------------------------------
@app.route("/")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    case = get_or_create_active_case(session["user_id"])
    return render_template("index.html", username=session.get("username"), active_case=case)


@app.route("/api/state", methods=["GET"])
def api_state():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    susp = require_suspicious_face_clear()
    if susp:
        return susp
    case = get_or_create_active_case(session["user_id"])
    if not authorize_case(case, "case:read"):
        return jsonify({"error": "Permission denied"}), 403
    return jsonify(build_case_state(case))


@app.route("/api/cases", methods=["GET", "POST"])
def api_cases():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user = current_user()
    if not user:
        return jsonify({"error": "Account not found"}), 401

    if request.method == "GET":
        assigned_ids = [m.case_id for m in CaseMembership.query.filter_by(user_id=user.id, is_active=True).all()]
        if role_code(user) in ("system_admin", "lead_investigator"):
            query = Case.query.filter_by(org_id=user.org_id or 1)
        elif assigned_ids:
            query = Case.query.filter(Case.org_id == (user.org_id or 1), (Case.user_id == user.id) | (Case.id.in_(assigned_ids)))
        else:
            query = Case.query.filter_by(user_id=user.id, org_id=user.org_id or 1)
        cases = query.order_by(Case.id.desc()).all()
        ids = [c.id for c in cases]
        counts = dict(db.session.query(Artifact.case_id, func.count(Artifact.id)).filter(
            Artifact.case_id.in_(ids), Artifact.retired_at.is_(None)).group_by(Artifact.case_id).all()) if ids else {}
        return jsonify({"cases": [{
            "id": c.id, "case_code": c.case_code, "title": c.title,
            "description": c.description or "", "status": c.status or "Active",
            "artifact_count": counts.get(c.id, 0),
        } for c in cases]})

    actor_role = role_code(user)
    if not role_has_permission(actor_role, "case:create"):
        return jsonify({"error": f"Role '{actor_role}' is not permitted to create cases."}), 403
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    description = (data.get("description") or "").strip()
    if not title:
        return jsonify({"error": "Enter a case title before creating the case."}), 400
    if len(title) > 150 or len(description) > 5000:
        return jsonify({"error": "Case title or description exceeds the allowed length."}), 400

    code = None
    for _ in range(10):
        candidate = f"#404-{secrets.token_hex(3).upper()}-{datetime.now().year}"
        if not Case.query.filter_by(case_code=candidate).first():
            code = candidate
            break
    if not code:
        return jsonify({"error": "Could not generate a unique case ID. Please try again."}), 503

    try:
        case = Case(case_code=code, title=title, description=description,
                    status="Active", user_id=user.id, org_id=user.org_id or 1)
        db.session.add(case)
        db.session.flush()
        db.session.add(ActivityLog(message=f"Created case {code}: {title}", case_id=case.id))
        db.session.commit()
        session["active_case_id"] = case.id
        session["active_case_user_id"] = user.id
    except Exception:
        db.session.rollback()
        app.logger.exception("Case database insert failed")
        return jsonify({"error": "Case database insert failed. No new case was committed."}), 500

    try:
        append_audit("CASE_CREATED", "case", case.id, details={"case_code": code})
    except Exception:
        app.logger.exception("Case created but audit append failed")
    return jsonify({"success": True, "state": build_case_state(case)})


@app.route("/api/cases/switch/<int:case_id>", methods=["POST"])
def api_switch_case(case_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    susp = require_suspicious_face_clear()
    if susp:
        return susp
    c = Case.query.filter_by(id=case_id).first()
    if not c or not authorize_case(c, "case:read"):
        return jsonify({"error": "Case not found or access denied"}), 404
    session["active_case_id"] = c.id
    session["active_case_user_id"] = session["user_id"]
    return jsonify({"success": True, "state": build_case_state(c)})


@app.route("/api/cases/<int:case_id>/status", methods=["POST"])
def api_update_case_status(case_id):
    gate = require_face_action("case_status")
    if gate:
        return gate
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    c = Case.query.filter_by(id=case_id).first()
    if not c or not authorize_case(c, "case:update"):
        return jsonify({"error": "Case not found or permission denied"}), 404
    data = request.get_json() or {}
    new_status = (data.get("status") or c.status).strip()
    if new_status not in {"New", "Active", "Under Review", "Awaiting Evidence", "Resolved", "Archived"}:
        return jsonify({"error": "Invalid case status."}), 400
    c.status = new_status
    db.session.commit()
    return jsonify({"success": True, "state": build_case_state(c)})


@app.route("/api/cases/<int:case_id>", methods=["DELETE"])
def api_delete_case(case_id):
    # Keep the existing live-face verification gate for destructive case actions.
    gate = require_face_action("case_delete")
    if gate:
        return gate
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    c = Case.query.filter_by(id=case_id).first()
    if not c:
        return jsonify({"error": "Case not found"}), 404
    if not authorize_case(c, "case:delete"):
        return jsonify({"error": "Permission denied"}), 403

    case_id_value = c.id
    case_code_value = c.case_code
    case_title_value = c.title
    actor_id = session["user_id"]

    # Collect only vault files whose resolved paths remain inside this app's vault.
    evidence_paths = []
    for artifact in Artifact.query.filter_by(case_id=case_id_value).all():
        if not artifact.storage_path:
            continue
        candidate = os.path.abspath(os.path.join(BASE_DIR, artifact.storage_path))
        try:
            if os.path.commonpath([VAULT_DIR, candidate]) == VAULT_DIR:
                evidence_paths.append(candidate)
        except ValueError:
            app.logger.warning("Skipped evidence cleanup outside vault for case %s", case_code_value)

    # Write the deletion event to the separate, hash-chained security audit log.
    try:
        append_audit(
            "CASE_PERMANENTLY_DELETED", "case", case_id_value,
            details={"case_code": case_code_value, "title": case_title_value,
                     "artifact_count": len(evidence_paths), "actor_user_id": actor_id}
        )
    except Exception:
        app.logger.exception("Could not write case deletion audit record")
        return jsonify({"error": "Deletion cancelled because the security audit record could not be written."}), 500

    try:
        # These tables reference Case without ORM delete cascades.
        CaseMembership.query.filter_by(case_id=case_id_value).delete(synchronize_session=False)
        TeamInviteLink.query.filter_by(case_id=case_id_value).delete(synchronize_session=False)
        db.session.delete(c)  # Case relationships cascade to artifacts, events, findings, etc.
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Permanent case deletion failed for case %s", case_code_value)
        return jsonify({"error": "The case could not be deleted. No database changes were committed."}), 500

    # Remove encrypted originals only after the database deletion commits.
    cleanup_failures = 0
    for path in evidence_paths:
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            cleanup_failures += 1
            app.logger.exception("Could not remove evidence-vault file after deleting case %s", case_code_value)

    remaining = Case.query.filter_by(user_id=actor_id).order_by(Case.id.desc()).first()
    if not remaining:
        remaining = get_or_create_active_case(actor_id)
    session["active_case_id"] = remaining.id
    session["active_case_user_id"] = actor_id
    state = build_case_state(remaining)
    return jsonify({
        "success": True,
        "deleted": True,
        "cleanup_warning": bool(cleanup_failures),
        "message": "Case permanently deleted." if not cleanup_failures else "Case deleted, but one or more stored evidence files need administrator cleanup.",
        "state": state
    })


@app.route("/api/admin/users/<int:target_user_id>/role", methods=["POST"])
def api_admin_change_role(target_user_id):
    gate = require_face_action("role_change")
    if gate:
        return gate
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    actor = current_user()
    data = request.get_json() or {}
    new_role = (data.get("role") or "").strip().lower()
    if not actor or role_code(actor) not in ("system_admin", "lead_investigator"):
        return jsonify({"error": "Only a lead investigator or system administrator can modify roles."}), 403
    if actor.id == target_user_id:
        return jsonify({"error": "Self-privilege modification is prohibited."}), 403
    if not is_valid_role(new_role) or (new_role == "system_admin" and role_code(actor) != "system_admin"):
        return jsonify({"error": "Invalid role or insufficient authority to assign system_admin."}), 403
    target = db.session.get(User, target_user_id)
    if not target or (target.org_id or 1) != (actor.org_id or 1):
        return jsonify({"error": "Target user not found in your organization."}), 403
    target.role = new_role
    db.session.commit()
    append_audit("USER_ROLE_CHANGED", "user", target.id, details={"new_role": new_role})
    return jsonify({"success": True, "user_id": target.id, "role": target.role})


@app.route("/api/cases/<int:case_id>/members", methods=["GET", "POST"])
def api_add_case_member(case_id):
    if request.method == "POST":
        gate = require_face_action("case_membership")
        if gate:
            return gate
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    case = Case.query.filter_by(id=case_id).first()
    if not case:
        return jsonify({"error": "Case not found."}), 404
    if request.method == "GET":
        if not authorize_case(case, "case:read"):
            return jsonify({"error": "Case access denied."}), 403
        users = User.query.filter_by(org_id=case.org_id, is_active=True).order_by(User.username.asc()).all()
        memberships = {m.user_id: m for m in CaseMembership.query.filter_by(case_id=case.id, is_active=True).all()}
        owner = db.session.get(User, case.user_id)
        members = [{"id": u.id, "username": u.username,
                    "role": memberships[u.id].role_override if memberships[u.id].role_override else role_code(u)}
                   for u in users if u.id in memberships and u.id != case.user_id]
        return jsonify({
            "owner": {"id": owner.id, "username": owner.username} if owner else None,
            "members": members,
            "users": [{"id": u.id, "username": u.username, "assigned": u.id in memberships,
                       "role": memberships[u.id].role_override if memberships[u.id].role_override else role_code(u)}
                      for u in users if u.id != case.user_id],
        })
    if not authorize_case(case, "case:assign"):
        return jsonify({"error": "Case assignment permission denied."}), 403
    data = request.get_json() or {}
    target = User.query.filter_by(username=(data.get("username") or "").strip()).first()
    role = (data.get("role") or "investigator").strip().lower()
    if not target or target.id == session["user_id"] or target.org_id != case.org_id or not is_valid_role(role) or role == "system_admin":
        return jsonify({"error": "Choose an existing user in the same organization and a valid non-admin case role."}), 400
    member = CaseMembership.query.filter_by(case_id=case.id, user_id=target.id).first()
    if member:
        member.role_override, member.is_active = role, True
    else:
        db.session.add(CaseMembership(case_id=case.id, user_id=target.id, role_override=role, is_active=True))
    db.session.commit()
    return jsonify({"success": True, "username": target.username, "role": role})


@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    case = get_or_create_active_case(session["user_id"])
    if not authorize_case(case, "evidence:upload"):
        return jsonify({"error": "Permission denied"}), 403
    gate = require_face_action("evidence_upload")
    if gate:
        return gate
    if "file" not in request.files or not request.files["file"].filename:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    safe_name = secure_filename(f.filename)
    ext = os.path.splitext(safe_name)[1].lower()
    raw_bytes = f.read(10 * 1024 * 1024 + 1)
    valid, reason = validate_evidence_content(raw_bytes, ext)
    if not valid:
        return jsonify({"error": reason}), 400

    digest = hashlib.sha256(raw_bytes).hexdigest()
    art_code = f"EV-{case.id}-{secrets.token_hex(4).upper()}"
    stored = None
    try:
        content_str = raw_bytes.decode("utf-8")
        parsed_items = dispatch_structured_parser(content_str, safe_name, art_code)
        stored = EVIDENCE_VAULT.store_original(raw_bytes, art_code, safe_name, case.id)
        coverage = f"{parsed_items[0]['timestamp_display']} -> {parsed_items[-1]['timestamp_display']}" if parsed_items else "No parseable timestamps"
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        uploader = session.get("username", "Investigator")
        history = [
            f"[{now_utc}] Ingested by {uploader} (Face verified)",
            f"[{now_utc}] SHA-256 verified ({digest[:16]}...)",
            f"[{now_utc}] Encrypted original stored (AES-256-GCM)",
            f"[{now_utc}] Parsed {len(parsed_items)} record(s)",
        ]
        art = Artifact(
            artifact_code=art_code, name=safe_name, original_filename=safe_name,
            log_type=ext.lstrip(".").upper() + " Artifact", sha256_hash=digest,
            file_size=len(raw_bytes), storage_path=os.path.relpath(stored["stored_path"], BASE_DIR),
            wrapped_dek=stored["wrapped_dek"], key_version=stored["key_version"],
            is_encrypted=True, uploaded_by=uploader, records_count=len(parsed_items),
            coverage_window=coverage, status="Verified",
            processing_history_json=json.dumps(history), uploaded_at=now_utc,
            case_id=case.id,
        )
        db.session.add(art)
        for item in parsed_items:
            db.session.add(LogEvent(
                event_dt=item["event_dt"], timestamp_display=item["timestamp_display"],
                original_tz=item["original_tz"], ips_csv=",".join(item["ips"]),
                username_entity=item["user"], file_entity=item["file"],
                process_entity=item["process"], description=item["description"],
                source_file=safe_name, artifact_code=art_code, case_id=case.id,
            ))
        db.session.add(ActivityLog(
            message=f"[{now_utc}] Encrypted ingestion of {safe_name} ({art_code}, SHA-256: {digest[:12]}...)",
            case_id=case.id,
        ))
        db.session.commit()
    except Exception:
        error_id = secrets.token_hex(4)
        db.session.rollback()
        if stored and stored.get("stored_path") and os.path.exists(stored["stored_path"]):
            try:
                os.chmod(stored["stored_path"], 0o600)
                os.remove(stored["stored_path"])
            except OSError:
                app.logger.exception("Could not remove uncommitted evidence-vault object")
        app.logger.exception("Evidence upload failed before metadata commit (error_id=%s)", error_id)
        return jsonify({"error": f"Evidence upload failed (reference {error_id}). No artifact was registered."}), 500

    try:
        append_audit("EVIDENCE_INGESTED", "artifact", art_code, details={"case_id": case.id, "sha256": digest, "encrypted": True})
        run_forensic_reasoning_engine(case, trigger_label=f"Ingested {safe_name} ({art_code})")
        db.session.commit()
        return jsonify({"success": True, "state": build_case_state(case)})
    except Exception:
        db.session.rollback()
        app.logger.exception("Evidence was stored, but post-ingestion reassessment failed")
        return jsonify({"success": True, "warning": "Evidence was securely stored, but automatic reassessment failed.", "state": build_case_state(case)})


@app.route("/api/evidence/<artifact_code>/content", methods=["GET"])
def api_view_evidence_content(artifact_code):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    case = get_or_create_active_case(session["user_id"])
    if not authorize_case(case, "evidence:read"):
        return jsonify({"error": "Permission denied"}), 403
    art = Artifact.query.filter_by(case_id=case.id, artifact_code=artifact_code).first()
    if not art:
        return jsonify({"error": "Artifact not found"}), 404
    raw_bytes, intact, message = EVIDENCE_VAULT.read_and_verify(art)
    if not intact or raw_bytes is None:
        return jsonify({"error": message, "intact": False}), 500
    text_content = raw_bytes.decode("utf-8", errors="replace")
    append_audit("EVIDENCE_VIEWED", "artifact", artifact_code, details={"case_id": case.id, "sha256_verified": True})
    return jsonify({
        "artifact_code": art.artifact_code,
        "name": art.name,
        "type": art.log_type,
        "sha256": art.sha256_hash,
        "file_size": art.file_size,
        "records_count": art.records_count,
        "coverage_window": art.coverage_window,
        "uploaded_by": art.uploaded_by,
        "uploaded_at": art.uploaded_at,
        "status": art.status,
        "intact": True,
        "integrity_message": message,
        "processing_history": json.loads(art.processing_history_json or "[]"),
        "content": text_content,
    })


@app.route("/api/evidence/<artifact_code>", methods=["DELETE"])
def api_delete_evidence(artifact_code):
    gate = require_face_action("evidence_retire")
    if gate:
        return gate
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    case = get_or_create_active_case(session["user_id"])
    if not authorize_case(case, "evidence:exclude"):
        return jsonify({"error": "Permission denied"}), 403
    art = Artifact.query.filter_by(case_id=case.id, artifact_code=artifact_code, retired_at=None).first()
    if not art:
        return jsonify({"error": "Artifact not found"}), 404
    removed_name = art.name
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    art.retired_at = now_utc
    art.status = "Retired - Original Preserved"
    history = json.loads(art.processing_history_json or "[]")
    history.append(f"[{now_utc}] Retired from active analysis by {session.get('username', 'Investigator')} (Face verified); immutable original preserved.")
    art.processing_history_json = json.dumps(history)
    db.session.add(ActivityLog(message=f"[{now_utc}] EVIDENCE_EXCLUDED: {removed_name} ({artifact_code}) retired from active analysis; immutable original retained.", case_id=case.id))
    db.session.commit()
    append_audit("EVIDENCE_RETIRED", "artifact", artifact_code, details={"case_id": case.id, "original_preserved": True})
    run_forensic_reasoning_engine(case, trigger_label=f"Retired {removed_name} ({artifact_code})")
    return jsonify({"success": True, "state": build_case_state(case)})


@app.route("/api/events/<int:event_id>/note", methods=["POST"])
def api_event_note(event_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    case = get_or_create_active_case(session["user_id"])
    if not authorize_case(case, "evidence:note"):
        return jsonify({"error": "Permission denied"}), 403
    gate = require_face_action("event_note")
    if gate:
        return gate
    ev = LogEvent.query.filter_by(id=event_id, case_id=case.id).first()
    if not ev:
        return jsonify({"error": "Event not found"}), 404
    data = request.get_json() or {}
    ev.investigator_note = (data.get("note") or "").strip()
    db.session.commit()
    return jsonify({"success": True, "state": build_case_state(case)})


@app.route("/api/compare", methods=["GET"])
def api_compare():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    case = get_or_create_active_case(session["user_id"])
    if not authorize_case(case, "case:read"):
        return jsonify({"error": "Permission denied"}), 403
    a_code = request.args.get("a", "")
    b_code = request.args.get("b", "")
    art_a = Artifact.query.filter_by(case_id=case.id, artifact_code=a_code, retired_at=None).first()
    art_b = Artifact.query.filter_by(case_id=case.id, artifact_code=b_code, retired_at=None).first()
    if not art_a or not art_b:
        return jsonify({"error": "Select two valid active artifacts to compare"}), 400

    ev_a = LogEvent.query.filter_by(case_id=case.id, artifact_code=art_a.artifact_code).order_by(LogEvent.event_dt.asc()).all()
    ev_b = LogEvent.query.filter_by(case_id=case.id, artifact_code=art_b.artifact_code).order_by(LogEvent.event_dt.asc()).all()

    ents_a = {e.username_entity for e in ev_a if e.username_entity} | {ip for e in ev_a for ip in e.ips_csv.split(",") if ip}
    ents_b = {e.username_entity for e in ev_b if e.username_entity} | {ip for e in ev_b for ip in e.ips_csv.split(",") if ip}
    shared = sorted(ents_a & ents_b)
    only_a = sorted(ents_a - ents_b)
    only_b = sorted(ents_b - ents_a)

    return jsonify({
        "artifact_a": {"code": art_a.artifact_code, "name": art_a.name, "coverage": art_a.coverage_window, "count": len(ev_a), "sha256": art_a.sha256_hash},
        "artifact_b": {"code": art_b.artifact_code, "name": art_b.name, "coverage": art_b.coverage_window, "count": len(ev_b), "sha256": art_b.sha256_hash},
        "shared_entities": shared,
        "only_in_a": only_a,
        "only_in_b": only_b,
        "events_a": [f"[{e.timestamp_display}] {e.description}" for e in ev_a],
        "events_b": [f"[{e.timestamp_display}] {e.description}" for e in ev_b],
    })


@app.route("/api/custody/verify", methods=["GET"])
def api_custody_verify():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    case = get_or_create_active_case(session["user_id"])
    if not authorize_case(case, "audit:verify"):
        return jsonify({"error": "Permission denied"}), 403
    results = []
    for art in Artifact.query.filter_by(case_id=case.id).all():
        _, intact, message = EVIDENCE_VAULT.read_and_verify(art)
        results.append({
            "artifact_code": art.artifact_code,
            "name": art.name,
            "intact": bool(intact),
            "message": message,
            "retired": bool(art.retired_at),
            "sha256": art.sha256_hash,
        })
    append_audit("CUSTODY_VERIFIED", "case", case.id, details={"artifact_count": len(results), "all_intact": all(r["intact"] for r in results)})
    return jsonify({"verified": all(r["intact"] for r in results), "artifacts": results})


@app.route("/api/reset-case", methods=["POST"])
def api_reset_case():
    gate = require_face_action("workspace_reset")
    if gate:
        return gate
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    case = get_or_create_active_case(session["user_id"])
    if not authorize_case(case, "case:update"):
        return jsonify({"error": "Permission denied"}), 403
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    for art in Artifact.query.filter_by(case_id=case.id, retired_at=None).all():
        art.retired_at = now_utc
        art.status = "Retired - Original Preserved"
    db.session.add(ActivityLog(message=f"[{now_utc}] Active workspace reset. Original evidence and custody metadata were preserved.", case_id=case.id))
    db.session.commit()
    run_forensic_reasoning_engine(case, trigger_label="Workspace reset; evidence originals retained")
    return jsonify({"success": True, "state": build_case_state(case)})


# -----------------------------------------------------------------------------
# Profile, Biometrics (WebAuthn & Face Recognition) & Backup Endpoints
# -----------------------------------------------------------------------------
@app.route("/api/profile", methods=["GET", "POST"])
def api_profile():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user = current_user()
    if not user:
        return jsonify({"error": "Account not found"}), 404
    if request.method == "POST":
        gate = require_face_action("profile_update")
        if gate:
            return gate
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return jsonify({"error": "Enter a valid email address."}), 400
        if User.query.filter(User.email == email, User.id != user.id).first():
            return jsonify({"error": "That email address is already registered."}), 409
        user.email = email
        db.session.commit()
        append_audit("PROFILE_EMAIL_CHANGED", "user", user.id)
    creds = json.loads(user.webauthn_credentials_json or "[]")
    rc = role_code(user)
    active_sessions = LoginSession.query.filter_by(user_id=user.id, revoked=False).filter(LoginSession.expires_at > datetime.utcnow()).count()
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "org_id": user.org_id or 1,
        "role": rc,
        "permissions": sorted(ROLE_PERMISSIONS.get(rc, set())),
        "sessions_count": active_sessions,
        "mfa_enabled": bool(user.mfa_enabled),
        "webauthn_count": len(creds),
        "passkeys": [{"id": c.get("id", "")[:16], "label": c.get("label", "Passkey")} for c in creds],
        "face_enrolled": bool(user.face_template_enc),
        "webauthn_supported": WEBAUTHN_AVAILABLE,
        "face_supported": FACE_VERIFICATION_AVAILABLE,
        "face_detection_supported": FACE_DETECTION_AVAILABLE,
    })


@app.route("/api/mfa/setup", methods=["POST"])
def api_mfa_setup():
    gate = require_face_action("mfa_setup")
    if gate:
        return gate
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user = current_user()
    data = request.get_json() or {}
    if not user or not user.check_password(data.get("password", "")):
        return jsonify({"error": "Confirm your current password before changing MFA settings."}), 400
    secret = generate_totp_secret()
    user.totp_pending_enc = encrypt_text_field(secret, KEY_MANAGER)
    db.session.commit()
    return jsonify({"secret": secret, "otpauth_uri": get_totp_uri(secret, user.username), "message": "Add this account to an authenticator app, then verify a code to enable MFA."})


@app.route("/api/mfa/enable", methods=["POST"])
def api_mfa_enable():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user = current_user()
    data = request.get_json() or {}
    try:
        secret = decrypt_text_field(user.totp_pending_enc or "", KEY_MANAGER)
    except Exception:
        secret = ""
    if not verify_totp(secret, data.get("code", "")):
        return jsonify({"error": "Authenticator code is invalid."}), 400
    from security.auth import generate_recovery_codes
    plain, hashed = generate_recovery_codes(8)
    user.totp_secret_enc = user.totp_pending_enc
    user.totp_pending_enc = None
    user.recovery_codes_json = json.dumps(hashed)
    user.mfa_enabled = True
    db.session.commit()
    return jsonify({"success": True, "recovery_codes": plain, "warning": "Save these recovery codes securely. They are shown only once."})


@app.route("/api/mfa/disable", methods=["POST"])
def api_mfa_disable():
    gate = require_face_action("mfa_disable")
    if gate:
        return gate
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user = current_user()
    data = request.get_json() or {}
    if not user.check_password(data.get("password", "")):
        return jsonify({"error": "Password confirmation failed."}), 400
    user.mfa_enabled = False
    user.totp_secret_enc = None
    user.totp_pending_enc = None
    user.recovery_codes_json = "[]"
    db.session.commit()
    return jsonify({"success": True})


@app.route("/api/webauthn/register/options", methods=["POST"])
def api_webauthn_reg_options():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    if not WEBAUTHN_AVAILABLE:
        return jsonify({"error": "WebAuthn dependency is not installed; passkey enrollment is unavailable."}), 503
    user = current_user()
    creds = json.loads(user.webauthn_credentials_json or "[]")
    try:
        options, options_json = registration_options(request, user_id=user.id, username=user.username, existing_ids=[c["id"] for c in creds])
    except Exception as exc:
        return jsonify({"error": f"Passkey domain/origin configuration is invalid: {exc}. Open CRIME404 at http://localhost:5000 for local testing, or configure HTTPS and WEBAUTHN_RP_ID/WEBAUTHN_ORIGIN."}), 400
    session["webauthn_challenge"] = b64url_encode(options.challenge)
    return jsonify({"options": json.loads(options_json)})


@app.route("/api/webauthn/register/verify", methods=["POST"])
def api_webauthn_reg_verify():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    if not WEBAUTHN_AVAILABLE:
        return jsonify({"error": "WebAuthn dependency is not installed."}), 503
    user = current_user()
    payload = request.get_json() or {}
    challenge = session.pop("webauthn_challenge", None)
    if not challenge:
        return jsonify({"error": "Registration challenge missing or expired. Request new options."}), 400
    try:
        verified = verify_registration(request, payload.get("credential", payload), b64url_decode(challenge))
        credential_id = b64url_encode(verified.credential_id)
        creds = json.loads(user.webauthn_credentials_json or "[]")
        if any(c.get("id") == credential_id for c in creds):
            return jsonify({"error": "This passkey is already registered."}), 409
        creds.append({
            "id": credential_id,
            "public_key": b64url_encode(verified.credential_public_key),
            "sign_count": verified.sign_count,
            "label": str(payload.get("label") or "Device / Hybrid Passkey")[:80],
        })
        user.webauthn_credentials_json = json.dumps(creds)
        db.session.commit()
        append_audit("PASSKEY_REGISTERED", "user", user.id, details={"count": len(creds)})
        return jsonify({"success": True, "webauthn_count": len(creds)})
    except Exception as exc:
        return jsonify({"error": f"Passkey registration verification failed: {str(exc)}"}), 400


@app.route("/api/webauthn/auth/options", methods=["POST"])
def api_webauthn_auth_options():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({"error": "WebAuthn dependency is not installed."}), 503
    user = current_user()
    if not user:
        return jsonify({"error": "Login required to start passkey authentication."}), 401
    creds = json.loads(user.webauthn_credentials_json or "[]")
    if not creds:
        return jsonify({"error": "No passkeys are registered."}), 404
    try:
        options, options_json = authentication_options(request, [c["id"] for c in creds])
    except Exception as exc:
        return jsonify({"error": f"Passkey domain/origin configuration is invalid: {exc}. Use localhost for local testing or configure HTTPS."}), 400
    session["webauthn_auth_challenge"] = b64url_encode(options.challenge)
    return jsonify({"options": json.loads(options_json)})


@app.route("/api/webauthn/auth/verify", methods=["POST"])
def api_webauthn_auth_verify():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({"error": "WebAuthn dependency is not installed."}), 503
    user = current_user()
    challenge = session.pop("webauthn_auth_challenge", None)
    payload = request.get_json() or {}
    if not user or not challenge:
        return jsonify({"error": "Authentication challenge missing."}), 400
    try:
        creds = json.loads(user.webauthn_credentials_json or "[]")
        cred_obj = payload.get("credential", payload)
        cred_id = cred_obj.get("id") or payload.get("id")
        item = next((c for c in creds if c["id"] == cred_id), None)
        if not item:
            return jsonify({"verified": False, "error": "Unknown credential."}), 400
        result = verify_authentication(request, cred_obj, b64url_decode(challenge), b64url_decode(item["public_key"]), int(item.get("sign_count", 0)))
        item["sign_count"] = result.new_sign_count
        user.webauthn_credentials_json = json.dumps(creds)
        db.session.commit()
        append_audit("PASSKEY_VERIFIED", "user", user.id)
        return jsonify({"verified": True})
    except Exception as exc:
        return jsonify({"verified": False, "error": str(exc)}), 400


@app.route("/api/face/enroll", methods=["POST"])
def api_face_enroll():
    if not current_user():
        return jsonify({"error": "Unauthorized"}), 401
    user = current_user()
    if not FACE_VERIFICATION_AVAILABLE:
        return jsonify({"error": "Face verification dependencies are unavailable."}), 503
    data = request.get_json(silent=True) or {}
    if not user.face_template_enc:
        if not user.check_password(data.get("current_password", "")):
            return jsonify({"error": "Confirm your current password to enroll your first face template."}), 400
        if user.mfa_enabled:
            try:
                secret = decrypt_text_field(user.totp_secret_enc or "", KEY_MANAGER)
            except Exception:
                secret = ""
            if not verify_totp(secret, data.get("mfa_code", "")):
                return jsonify({"error": "A valid authenticator code is required to enroll your face."}), 400
    try:
        store_face_template(user, data.get("images"))
        db.session.commit()
        append_audit("FACE_TEMPLATE_ENROLLED", "user", session["user_id"])
        return jsonify({"success": True, "message": "Face template encrypted and enrolled."})
    except (ValueError, face_service.FaceServiceUnavailable) as exc:
        db.session.rollback()
        return jsonify({"error": str(exc)}), 400


@app.route("/api/face/verify", methods=["POST"])
def api_face_verify():
    user = current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    if not FACE_VERIFICATION_AVAILABLE:
        return jsonify({"verified": False, "error": "Face verification engine unavailable."}), 503
    if not user.face_template_enc:
        return jsonify({"verified": False, "error": "No enrolled face template exists. Please enroll your face in My Profile & Biometrics first.", "face_not_enrolled": True}), 409
    throttle_key = f"face:{user.id}"
    blocked, retry_after = LOGIN_THROTTLE.is_blocked(throttle_key, request.remote_addr or "unknown")
    if blocked:
        return jsonify({"verified": False, "error": f"Too many face verification attempts. Try again in {retry_after} seconds."}), 429
    data = request.get_json(silent=True) or {}
    action = str(data.get("action") or "manual_verify")
    if not re.fullmatch(r"[a-z_]{3,40}", action):
        return jsonify({"verified": False, "error": "Invalid verification action."}), 400
    try:
        import base64
        template_b64 = decrypt_text_field(user.face_template_enc, KEY_MANAGER)
        matched, distance = face_service.verify_template(data.get("image", ""), base64.b64decode(template_b64))
        if not matched:
            LOGIN_THROTTLE.record_failure(throttle_key, request.remote_addr or "unknown")
            append_audit("FACE_VERIFICATION_FAILED", "user", user.id, outcome="FAILURE", details={"action": action})
            return jsonify({"verified": False, "error": "Face verification failed — face did not match enrolled investigator."}), 401
        LOGIN_THROTTLE.record_success(throttle_key, request.remote_addr or "unknown")
        session["face_verified_action"] = {"action": action, "expires": datetime.now(timezone.utc).timestamp() + 90}
        if action == "suspicious_activity_challenge":
            session.pop("suspicious_activity_flag", None)
            session.pop("suspicious_reason", None)
        append_audit("FACE_VERIFICATION_SUCCESS", "user", user.id, details={"action": action})
        return jsonify({"verified": True, "action": action, "distance": round(distance, 4), "expires_in": 90})
    except (ValueError, face_service.FaceServiceUnavailable) as exc:
        return jsonify({"verified": False, "error": str(exc)}), 400
    except Exception:
        app.logger.exception("Face verification failed")
        return jsonify({"verified": False, "error": "Face verification could not be completed."}), 400


@app.route("/api/face/detect", methods=["POST"])
def api_face_detect():
    if "user_id" not in session:
        return jsonify({"error": "Login required"}), 401
    if not FACE_DETECTION_AVAILABLE:
        return jsonify({"error": "Face detection engine unavailable. Install opencv-python-headless and restart CRIME404."}), 503
    data = request.get_json(silent=True) or {}
    image_data = data.get("image", "")
    if not isinstance(image_data, str) or not image_data.startswith("data:image/jpeg;base64,"):
        return jsonify({"error": "Expected a JPEG camera frame"}), 400
    encoded = image_data.split(",", 1)[1]
    if len(encoded) > 1_400_000:
        return jsonify({"error": "Frame exceeds the 1 MB limit"}), 413
    try:
        import base64
        raw = base64.b64decode(encoded, validate=True)
        if not raw or len(raw) > 1_000_000:
            return jsonify({"error": "Frame exceeds the 1 MB limit"}), 413
        arr = np.frombuffer(raw, dtype=np.uint8)
        frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if frame is None:
            return jsonify({"error": "Unable to decode camera frame"}), 400
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        cascade_path = os.path.join(cv2.data.haarcascades, "haarcascade_frontalface_default.xml")
        detector = cv2.CascadeClassifier(cascade_path)
        if detector.empty():
            return jsonify({"error": "Face detection model could not be loaded"}), 503
        faces = detector.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(48, 48))
        return jsonify({
            "detected": len(faces) > 0,
            "face_count": int(len(faces)),
            "message": "Face detected" if len(faces) else "No face detected",
        })
    except Exception:
        return jsonify({"error": "Camera frame processing failed"}), 400


@app.route("/api/profile/delete", methods=["POST"])
def api_profile_delete():
    """Deactivate the signed-in account while retaining case/evidence provenance."""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = current_user()
    if not user or not user.is_active:
        return jsonify({"error": "Account not found or already deactivated."}), 404

    data = request.get_json(silent=True) or {}
    if data.get("confirmation") != "DELETE":
        return jsonify({"error": 'Type DELETE in the confirmation field to continue.'}), 400
    if not user.check_password(data.get("current_password") or ""):
        return jsonify({"error": "Current password is incorrect."}), 400

    user_id = user.id
    try:
        # Keep the user row and case relationships so historical forensic records,
        # evidence custody, memberships, and audit references remain intact.
        append_audit(
            "ACCOUNT_DEACTIVATED",
            "user",
            user_id,
            details={"case_records_preserved": True, "reason": "self_service_profile_deletion"},
        )
        user.is_active = False
        user.username = f"deactivated_investigator_{user_id}"
        user.email = f"deactivated+{user_id}@invalid.local"
        user.password_hash = hash_password(secrets.token_urlsafe(48))
        user.reset_token = None
        user.reset_expires_at = None
        user.webauthn_credentials_json = "[]"
        user.face_template_hash = None
        user.face_template_enc = None
        user.mfa_enabled = False
        user.totp_secret_enc = None
        user.totp_pending_enc = None
        user.recovery_codes_json = "[]"
        LoginSession.query.filter_by(user_id=user_id).update({"revoked": True})
        CaseMembership.query.filter_by(user_id=user_id).update({"is_active": False})
        TeamInviteLink.query.filter_by(created_by_id=user_id).update({"is_active": False})
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Self-service account deactivation failed for user %s", user_id)
        return jsonify({"error": "The profile could not be deactivated. No account changes were committed."}), 500

    session.clear()
    return jsonify({
        "success": True,
        "message": "Profile deactivated. Your forensic case records and evidence custody history were preserved.",
        "redirect": url_for("login"),
    })


@app.route("/api/profile/password", methods=["POST"])
def api_profile_change_password():
    gate = require_face_action("password_change")
    if gate:
        return gate
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user = User.query.get(session["user_id"])
    data = request.get_json() or {}
    current = data.get("current_password") or ""
    new_password = data.get("new_password") or ""
    if not user or not user.check_password(current):
        return jsonify({"error": "Current password is incorrect."}), 400
    valid, reason = validate_password_strength(new_password, username=user.username, email=user.email)
    if not valid:
        return jsonify({"error": reason}), 400
    user.set_password(new_password)
    LoginSession.query.filter_by(user_id=user.id).update({"revoked": True})
    db.session.commit()
    session.clear()
    return jsonify({"success": True, "relogin_required": True, "message": "Password changed successfully."})


@app.route("/api/face/remove", methods=["POST"])
def api_face_remove():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user = User.query.get(session["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404
    user.face_template_enc = None
    user.face_template_hash = None
    db.session.commit()
    append_audit("FACE_TEMPLATE_REMOVED", "user", user.id)
    return jsonify({"success": True, "message": "Face template removed."})


@app.route("/api/authorize/export", methods=["POST"])
def api_authorize_export():
    if not current_user():
        return jsonify({"error": "Unauthorized"}), 401
    case = get_or_create_active_case(session["user_id"])
    if not authorize_case(case, "export:report"):
        return jsonify({"error": "Export permission denied."}), 403
    gate = require_face_action("report_export")
    if gate:
        return gate
    append_audit("FORENSIC_REPORT_EXPORTED", "case", case.id)
    return jsonify({"success": True})


@app.route("/api/backup/run", methods=["POST"])
def api_backup_run():
    gate = require_face_action("backup_create")
    if gate:
        return gate
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user = current_user()
    if role_code(user) not in ("system_admin", "lead_investigator"):
        return jsonify({"error": "Only an authorized lead investigator or system administrator can create backups."}), 403
    db_path = os.path.join(INSTANCE_DIR, "crime404_users.db")
    try:
        result = create_encrypted_backup(db_path, ORIGINALS_DIR, BACKUPS_DIR, KEY_MANAGER, initiated_by=user.username, keyring_path=KEY_MANAGER._key_file_path())
        pruned = prune_old_backups(BACKUPS_DIR, keep_last=10)
        public_result = {key: result[key] for key in ("backup_filename", "plaintext_sha256", "size_bytes", "file_count", "rpo_minutes", "rto_minutes")}
        public_result["pruned_old_backups"] = pruned
        append_audit("ENCRYPTED_BACKUP_CREATED", "backup", result["backup_filename"], details={"file_count": result["file_count"], "sha256": result["plaintext_sha256"]})
        return jsonify({"success": True, "backup": public_result})
    except Exception:
        app.logger.exception("Encrypted backup failed")
        return jsonify({"success": False, "error": "Encrypted backup failed. No placeholder backup was created."}), 500


if __name__ == "__main__":
    print("=" * 68)
    print("  CRIME404 — Intelligent Digital Forensic Investigation System")
    print("  Server running at: http://localhost:5000")
    print("=" * 68)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
