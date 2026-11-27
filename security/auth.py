"""
CRIME404 Authentication, MFA, Session Protection & Login Throttling (Checklist Section 1 & 3)
- Password Policy: min 12 chars, compromised-password check, no arbitrary symbol rules.
- Password Storage: Argon2id (via argon2-cffi) with automatic scrypt fallback if argon2-cffi
  is absent in a minimal runtime, plus transparent upgrade of legacy werkzeug hashes.
- MFA: Pure-Python RFC 6238 TOTP (compatible with Google Authenticator / Authy / 1Password)
  and single-use hashed recovery codes.
- Login Protection: Sliding-window rate limiting, temporary lockout, suspicious IP/UA detection.
- Password Reset: Short-lived (15 min), single-use, SHA-256-hashed reset tokens.
- Sessions: Server-side session table with expiry, revocation, and logout-all-devices.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

try:
    from argon2 import PasswordHasher, Type as Argon2Type
    from argon2.exceptions import VerifyMismatchError, VerificationError
    _ARGON2_HASHER = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
        type=Argon2Type.ID,
    )
    HAS_ARGON2 = True
except ImportError:
    _ARGON2_HASHER = None
    HAS_ARGON2 = False

try:
    from werkzeug.security import check_password_hash as _legacy_werkzeug_check
except ImportError:
    _legacy_werkzeug_check = None


MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

# Representative compromised / breached password blocklist (lowercase normalized)
COMPROMISED_PASSWORDS = {
    "123456", "123456789", "12345678", "1234567890", "123456789012",
    "password", "password123", "password1234", "qwerty123456", "admin1234567",
    "letmein12345", "welcome12345", "iloveyou1234", "crime404", "crime4041234",
    "forensic1234", "investigator", "administrator", "changeme1234",
    "p@ssw0rd1234", "qwertyuiop12", "111111111111", "000000000000",
    "abc123456789", "monkey123456", "dragon123456", "baseball1234",
    "football1234", "trustno11234", "sunshine1234", "princess1234",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def validate_password_strength(password: str, username: str = "", email: str = "") -> Tuple[bool, str]:
    """
    Validates password against NIST SP 800-63B / OWASP ASVS guidelines:
    - Minimum 12 characters, max 128 characters
    - Not in known compromised-password list
    - Not equal to username or email local-part
    - Not a single repeated character
    """
    if not password or not isinstance(password, str):
        return False, "Password is required."
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f"Password must not exceed {MAX_PASSWORD_LENGTH} characters."
    norm = password.strip().lower()
    if norm in COMPROMISED_PASSWORDS:
        return False, "This password appears in known compromised-password lists. Choose a unique passphrase."
    if len(set(password)) <= 2:
        return False, "Password has insufficient character variety; avoid repeated characters."
    if username and username.strip().lower() in norm and len(username.strip()) >= 4:
        return False, "Password should not contain your username."
    if email and "@" in email:
        local = email.split("@", 1)[0].strip().lower()
        if len(local) >= 4 and local in norm:
            return False, "Password should not contain your email address."
    return True, "OK"


def hash_password(password: str) -> str:
    """Hashes password using Argon2id (unique salt) when available, else scrypt."""
    if HAS_ARGON2:
        return _ARGON2_HASHER.hash(password)
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$" + base64.b64encode(salt).decode("ascii") + "$" + base64.b64encode(dk).decode("ascii")


def verify_password(stored_hash: str, password: str) -> Tuple[bool, bool]:
    """
    Verifies password against stored hash.
    Returns (is_valid, needs_rehash).
    """
    if not stored_hash or not password:
        return False, False

    if stored_hash.startswith("$argon2"):
        if not HAS_ARGON2:
            return False, False
        try:
            ok = _ARGON2_HASHER.verify(stored_hash, password)
            return ok, _ARGON2_HASHER.check_needs_rehash(stored_hash)
        except (VerifyMismatchError, VerificationError):
            return False, False

    if stored_hash.startswith("scrypt$"):
        try:
            _, n_s, r_s, p_s, salt_b64, dk_b64 = stored_hash.split("$", 5)
            salt = base64.b64decode(salt_b64)
            expected = base64.b64decode(dk_b64)
            actual = hashlib.scrypt(
                password.encode("utf-8"), salt=salt, n=int(n_s), r=int(r_s), p=int(p_s), dklen=len(expected)
            )
            ok = hmac.compare_digest(actual, expected)
            return ok, HAS_ARGON2  # upgrade to Argon2id if argon2-cffi is available
        except Exception:
            return False, False

    # Legacy Werkzeug PBKDF2/scrypt hash upgrade path
    if _legacy_werkzeug_check is not None:
        try:
            if _legacy_werkzeug_check(stored_hash, password):
                return True, True
        except Exception:
            pass
    return False, False


# ---------------- RFC 6238 TOTP MFA & Recovery Codes ----------------

def generate_totp_secret(length_bytes: int = 20) -> str:
    """Generates a Base32-encoded TOTP secret."""
    return base64.b32encode(secrets.token_bytes(length_bytes)).decode("ascii").rstrip("=")


def get_totp_uri(secret: str, username: str, issuer: str = "CRIME404") -> str:
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    pad_len = (-len(secret_b32)) % 8
    key = base64.b32decode(secret_b32.upper() + ("=" * pad_len), casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10 ** digits)).zfill(digits)


def verify_totp(secret_b32: str, code: str, window: int = 1, now_ts: Optional[int] = None) -> bool:
    """Verifies a 6-digit TOTP code within +/- `window` 30-second steps."""
    if not secret_b32 or not code:
        return False
    cleaned = "".join(ch for ch in str(code).strip() if ch.isdigit())
    if len(cleaned) != 6:
        return False
    ts = int(now_ts if now_ts is not None else time.time())
    counter = ts // 30
    for offset in range(-window, window + 1):
        expected = _hotp(secret_b32, counter + offset)
        if hmac.compare_digest(expected, cleaned):
            return True
    return False


def generate_recovery_codes(count: int = 8) -> Tuple[List[str], List[str]]:
    """
    Generates `count` single-use recovery codes.
    Returns (plaintext_codes_for_user, sha256_hashed_codes_for_db).
    """
    plain = []
    hashed = []
    for _ in range(count):
        raw = f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
        plain.append(raw)
        hashed.append(hashlib.sha256(raw.encode("utf-8")).hexdigest())
    return plain, hashed


def verify_and_consume_recovery_code(code: str, stored_hashes: List[str]) -> Tuple[bool, List[str]]:
    """Checks a recovery code against stored SHA-256 hashes and removes it if valid."""
    if not code or not stored_hashes:
        return False, stored_hashes
    norm = code.strip().upper()
    candidate = hashlib.sha256(norm.encode("utf-8")).hexdigest()
    for idx, h in enumerate(stored_hashes):
        if hmac.compare_digest(h, candidate):
            remaining = stored_hashes[:idx] + stored_hashes[idx + 1:]
            return True, remaining
    return False, stored_hashes


# ---------------- Login Attempt Protection & Suspicious Pattern Detection ----------------

class LoginThrottle:
    """
    In-memory + DB-friendly sliding-window rate limiter & temporary account lockout.
    Blocks brute-force attempts per (identifier, ip) and flags suspicious patterns.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300, lockout_seconds: int = 900):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._failures: Dict[str, List[float]] = {}
        self._locked_until: Dict[str, float] = {}

    def _keys(self, identifier: str, ip_addr: str) -> List[str]:
        ident = (identifier or "").strip().lower()
        ip = (ip_addr or "unknown").strip()
        return [f"user:{ident}", f"ip:{ip}"]

    def is_blocked(self, identifier: str, ip_addr: str, now: Optional[float] = None) -> Tuple[bool, int]:
        t = now if now is not None else time.time()
        for k in self._keys(identifier, ip_addr):
            until = self._locked_until.get(k, 0.0)
            if until > t:
                return True, int(until - t)
        return False, 0

    def record_failure(self, identifier: str, ip_addr: str, now: Optional[float] = None) -> Tuple[bool, int]:
        """Records a failed login; returns (locked_now, remaining_attempts)."""
        t = now if now is not None else time.time()
        cutoff = t - self.window_seconds
        locked_now = False
        min_remaining = self.max_attempts
        for k in self._keys(identifier, ip_addr):
            attempts = [ts for ts in self._failures.get(k, []) if ts >= cutoff]
            attempts.append(t)
            self._failures[k] = attempts
            rem = max(0, self.max_attempts - len(attempts))
            if rem < min_remaining:
                min_remaining = rem
            if len(attempts) >= self.max_attempts:
                self._locked_until[k] = t + self.lockout_seconds
                locked_now = True
        return locked_now, min_remaining

    def record_success(self, identifier: str, ip_addr: str) -> None:
        for k in self._keys(identifier, ip_addr):
            self._failures.pop(k, None)
            self._locked_until.pop(k, None)


def hash_token(raw_token: str) -> str:
    """Hashes session or reset tokens with SHA-256 before DB storage."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def is_suspicious_login(user_last_ip: Optional[str], user_last_ua: Optional[str], ip: str, ua: str) -> bool:
    """Detects new IP or new User-Agent compared to the user's prior successful login."""
    if not user_last_ip:
        return False
    if user_last_ip != ip:
        return True
    if user_last_ua and ua and user_last_ua[:80] != ua[:80]:
        return True
    return False
