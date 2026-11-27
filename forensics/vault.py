"""
CRIME404 Evidence Vault Security & Forensic Integrity (Checklist Section 5)
- Secure evidence ingestion: extension allowlist, magic-byte / executable rejection,
  UTF-8 content validation, size limit, quarantine staging, safe internal filenames.
- Separation of original encrypted evidence (originals/) from controlled working copies (working/).
- Envelope encryption at rest (AES-256-GCM) via KeyManager.
- SHA-256 integrity verification on ingestion, access, and export.
"""

import hashlib
import json
import os
import secrets
from typing import Optional, Tuple

from security.crypto import KeyManager, encrypt_bytes_envelope, decrypt_bytes_envelope

ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json"}
MAX_EVIDENCE_BYTES = 10 * 1024 * 1024  # 10 MB default limit

# Executable / binary / archive signatures to reject even if renamed to .log/.txt
DANGEROUS_MAGIC_PREFIXES = (
    b"MZ",                  # Windows PE/EXE/DLL
    b"\x7fELF",             # Linux ELF binary
    b"\xca\xfe\xba\xbe",    # Mach-O universal / Java class
    b"\xcf\xfa\xed\xfe",    # Mach-O 64-bit
    b"\xfe\xed\xfa\xce",    # Mach-O 32-bit
    b"PK\x03\x04",          # ZIP / Office / JAR archive (prevent archive bombs)
    b"Rar!\x1a\x07",        # RAR archive
    b"\x1f\x8b\x08",        # GZIP archive
    b"%PDF-",               # PDF (not a supported text log format)
)


def validate_evidence_content(raw_bytes: bytes, ext: str) -> Tuple[bool, str]:
    """
    Validates actual file contents (not just extension):
    - Non-empty and within MAX_EVIDENCE_BYTES
    - Rejects known executable/archive magic bytes
    - Rejects NUL bytes (binary disguised as text)
    - Validates UTF-8 decodability and JSON syntax for .json files
    """
    if not raw_bytes:
        return False, "Uploaded file is empty (0 bytes)."
    if len(raw_bytes) > MAX_EVIDENCE_BYTES:
        return False, f"File exceeds maximum allowed size ({MAX_EVIDENCE_BYTES} bytes)."
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Unsupported file format '{ext}'."

    for sig in DANGEROUS_MAGIC_PREFIXES:
        if raw_bytes.startswith(sig):
            return False, "Security violation: file content matches a disallowed binary or archive signature."

    if b"\x00" in raw_bytes[:4096]:
        return False, "Security violation: binary NUL bytes detected in text evidence file."

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return False, "File is not valid UTF-8 text."

    if ext == ".json":
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON structure: {exc}"

    return True, "OK"


class EvidenceVault:
    """
    Manages encrypted original evidence storage and isolated working copies.
    Originals are encrypted with AES-256-GCM and stored in `originals/` with 0o400/0o600
    permissions; working copies are placed in `working/` only during controlled processing.
    """

    def __init__(self, vault_root: str, key_manager: KeyManager):
        self.vault_root = vault_root
        self.originals_dir = os.path.join(vault_root, "originals")
        self.working_dir = os.path.join(vault_root, "working")
        self.quarantine_dir = os.path.join(vault_root, "quarantine")
        self.key_manager = key_manager
        for d in (self.vault_root, self.originals_dir, self.working_dir, self.quarantine_dir):
            os.makedirs(d, exist_ok=True)
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass

    def store_original(
        self,
        raw_bytes: bytes,
        artifact_code: str,
        safe_name: str,
        case_id: int,
    ) -> dict:
        """
        Stages in quarantine, computes SHA-256, encrypts with AES-256-GCM envelope,
        writes immutable encrypted original to `originals/`, and cleans quarantine.
        """
        sha256_digest = hashlib.sha256(raw_bytes).hexdigest()
        internal_name = f"case{case_id}_{artifact_code}_{sha256_digest[:12]}_{secrets.token_hex(4)}.enc"
        quarantine_path = os.path.join(self.quarantine_dir, internal_name + ".tmp")
        final_path = os.path.join(self.originals_dir, internal_name)

        with open(quarantine_path, "xb") as qf:
            qf.write(raw_bytes)
        try:
            os.chmod(quarantine_path, 0o600)
        except OSError:
            pass

        try:
            aad = f"case:{case_id}|artifact:{artifact_code}|sha256:{sha256_digest}".encode("utf-8")
            env = encrypt_bytes_envelope(raw_bytes, self.key_manager, aad=aad)
            with open(final_path, "wb") as out_f:
                out_f.write(env["ciphertext"])
            try:
                os.chmod(final_path, 0o400)
            except OSError:
                pass
        finally:
            if os.path.exists(quarantine_path):
                os.remove(quarantine_path)

        return {
            "stored_path": final_path,
            "sha256_hash": sha256_digest,
            "wrapped_dek": env["wrapped_dek"],
            "key_version": env["key_version"],
            "is_encrypted": True,
        }

    def create_working_copy(self, artifact) -> Tuple[Optional[str], bool, str]:
        """
        Decrypts (or reads legacy plaintext) original into `working/` after verifying
        SHA-256 integrity. Returns (working_path, intact, message).
        """
        raw_bytes, intact, msg = self.read_and_verify(artifact)
        if not intact or raw_bytes is None:
            return None, False, msg
        work_name = f"work_{artifact.artifact_code}_{secrets.token_hex(4)}_{artifact.original_filename}"
        work_path = os.path.join(self.working_dir, work_name)
        with open(work_path, "wb") as wf:
            wf.write(raw_bytes)
        return work_path, True, "Working copy created and SHA-256 verified."

    def read_and_verify(self, artifact) -> Tuple[Optional[bytes], bool, str]:
        """Reads original evidence (decrypting if encrypted) and verifies SHA-256."""
        path = artifact.stored_path
        if not path or not os.path.exists(path):
            return None, False, "Original evidence file is missing from vault."

        with open(path, "rb") as f:
            blob = f.read()

        if getattr(artifact, "is_encrypted", False) and getattr(artifact, "wrapped_dek", ""):
            try:
                aad = f"case:{artifact.case_id}|artifact:{artifact.artifact_code}|sha256:{artifact.sha256_hash}".encode("utf-8")
                plaintext = decrypt_bytes_envelope(
                    blob, artifact.wrapped_dek, artifact.key_version, self.key_manager, aad=aad
                )
            except Exception as exc:
                return None, False, f"Decryption/authentication failed (possible tampering): {exc}"
        else:
            plaintext = blob

        actual_hash = hashlib.sha256(plaintext).hexdigest()
        if actual_hash != artifact.sha256_hash:
            return None, False, f"SHA-256 mismatch: expected {artifact.sha256_hash[:12]}..., got {actual_hash[:12]}..."

        return plaintext, True, "Integrity verified (SHA-256 match)."
