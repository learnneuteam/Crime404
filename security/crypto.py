"""
CRIME404 Encryption at Rest, Key Management & Transport Security (Checklist Section 4)
- Envelope encryption using AES-256-GCM (authenticated encryption).
- Key separation: Master Key Encryption Key (KEK) is stored via environment variable
  or an isolated key-store directory outside evidence_vault_storage/ and instance/.
- Supports key rotation (re-wrapping DEKs without re-encrypting large evidence blobs).
- Provides HTTP security headers & HTTPS enforcement helpers.
"""

import os
import base64
import json
import secrets
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyManager:
    """Manages KEK (Key Encryption Key) separation, versioning, and DEK wrapping."""

    def __init__(self, key_store_dir: str = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.key_store_dir = key_store_dir or os.environ.get(
            "CRIME404_KEY_STORE_DIR", os.path.join(base_dir, "keys_isolated")
        )
        os.makedirs(self.key_store_dir, exist_ok=True)
        try:
            os.chmod(self.key_store_dir, 0o700)
        except OSError:
            pass
        self._keys: Dict[str, bytes] = {}
        self._active_version: str = "v1"
        self._load_or_init_keys()

    def _key_file_path(self) -> str:
        return os.path.join(self.key_store_dir, "keyring.json")

    def _load_or_init_keys(self) -> None:
        env_master = os.environ.get("CRIME404_MASTER_KEY", "").strip()
        if env_master:
            raw = base64.urlsafe_b64decode(env_master.encode("utf-8"))
            if len(raw) != 32:
                raise ValueError("CRIME404_MASTER_KEY must decode to 32 bytes (AES-256).")
            self._keys["v1"] = raw
            self._active_version = os.environ.get("CRIME404_ACTIVE_KEY_VERSION", "v1")
            return

        kf = self._key_file_path()
        if os.path.exists(kf):
            with open(kf, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._active_version = data.get("active_version", "v1")
            for ver, b64_key in data.get("keys", {}).items():
                self._keys[ver] = base64.urlsafe_b64decode(b64_key.encode("utf-8"))
        else:
            self._keys["v1"] = AESGCM.generate_key(bit_length=256)
            self._active_version = "v1"
            self._persist_keyring()

    def _persist_keyring(self) -> None:
        payload = {
            "active_version": self._active_version,
            "keys": {
                ver: base64.urlsafe_b64encode(k).decode("utf-8")
                for ver, k in self._keys.items()
            },
        }
        kf = self._key_file_path()
        with open(kf, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        try:
            os.chmod(kf, 0o600)
        except OSError:
            pass

    @property
    def active_version(self) -> str:
        return self._active_version

    def rotate_master_key(self) -> str:
        """Generates a new KEK version and marks it active for future wrapping."""
        next_num = len(self._keys) + 1
        new_ver = f"v{next_num}"
        self._keys[new_ver] = AESGCM.generate_key(bit_length=256)
        self._active_version = new_ver
        self._persist_keyring()
        return new_ver

    def wrap_dek(self, dek: bytes) -> Tuple[str, str]:
        """Encrypts a 32-byte Data Encryption Key (DEK) with the active KEK."""
        kek = self._keys[self._active_version]
        nonce = secrets.token_bytes(12)
        ct = AESGCM(kek).encrypt(nonce, dek, b"crime404-dek-wrap")
        wrapped = base64.urlsafe_b64encode(nonce + ct).decode("utf-8")
        return wrapped, self._active_version

    def unwrap_dek(self, wrapped_b64: str, key_version: str) -> bytes:
        """Decrypts a wrapped DEK using the recorded KEK version."""
        if key_version not in self._keys:
            raise KeyError(f"Key version '{key_version}' not found in keyring.")
        raw = base64.urlsafe_b64decode(wrapped_b64.encode("utf-8"))
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(self._keys[key_version]).decrypt(nonce, ct, b"crime404-dek-wrap")


def encrypt_bytes_envelope(plaintext: bytes, key_manager: KeyManager, aad: bytes = b"") -> Dict[str, Any]:
    """
    Encrypts evidence bytes using a fresh 256-bit DEK (AES-256-GCM),
    then wraps the DEK with the KEK. Returns ciphertext bytes + envelope metadata.
    """
    dek = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    wrapped_dek, key_version = key_manager.wrap_dek(dek)
    return {
        "ciphertext": nonce + ciphertext,
        "wrapped_dek": wrapped_dek,
        "key_version": key_version,
        "algorithm": "AES-256-GCM",
    }


def decrypt_bytes_envelope(
    encrypted_blob: bytes,
    wrapped_dek: str,
    key_version: str,
    key_manager: KeyManager,
    aad: bytes = b"",
) -> bytes:
    """Decrypts an AES-256-GCM envelope-encrypted blob."""
    dek = key_manager.unwrap_dek(wrapped_dek, key_version)
    nonce, ciphertext = encrypted_blob[:12], encrypted_blob[12:]
    return AESGCM(dek).decrypt(nonce, ciphertext, aad)


def encrypt_text_field(plaintext: str, key_manager: KeyManager) -> str:
    """Encrypts sensitive configuration/secret strings (e.g., TOTP secrets) at rest."""
    if not plaintext:
        return ""
    env = encrypt_bytes_envelope(plaintext.encode("utf-8"), key_manager, aad=b"crime404-field")
    payload = {
        "v": env["key_version"],
        "w": env["wrapped_dek"],
        "c": base64.urlsafe_b64encode(env["ciphertext"]).decode("utf-8"),
    }
    return "ENC:" + base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")


def decrypt_text_field(token: str, key_manager: KeyManager) -> str:
    """Decrypts an ENC:... field encrypted by encrypt_text_field."""
    if not token:
        return ""
    if not token.startswith("ENC:"):
        return token
    raw = json.loads(base64.urlsafe_b64decode(token[4:].encode("utf-8")).decode("utf-8"))
    ct = base64.urlsafe_b64decode(raw["c"].encode("utf-8"))
    pt = decrypt_bytes_envelope(ct, raw["w"], raw["v"], key_manager, aad=b"crime404-field")
    return pt.decode("utf-8")


def apply_security_headers(response, force_https: bool = False):
    """Applies OWASP-recommended HTTP security headers to Flask responses."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(self), microphone=(), geolocation=()",
    )
    if force_https:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response
