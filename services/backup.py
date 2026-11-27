"""
CRIME404 Encrypted Backup & Disaster Recovery Service (Checklist Section 7)
- Creates consistent SQLite online backups (WAL-safe) + encrypted evidence vault copies.
- Packages and encrypts the entire backup bundle with AES-256-GCM via KeyManager.
- Stores backups in a separate `backups_isolated/` directory (never inside instance/ or vault).
- Supports full restoration & post-restore SHA-256 hash verification.
- Target RPO: <= 15 minutes (or on-demand before critical ops); Target RTO: <= 30 minutes.
"""

import hashlib
import io
import json
import os
import shutil
import sqlite3
import tarfile
from datetime import datetime, timezone
from typing import Dict, Any, Tuple

from security.crypto import KeyManager, encrypt_bytes_envelope, decrypt_bytes_envelope


DEFAULT_RPO_MINUTES = 15
DEFAULT_RTO_MINUTES = 30


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def create_encrypted_backup(
    db_path: str,
    vault_originals_dir: str,
    backup_dir: str,
    key_manager: KeyManager,
    initiated_by: str = "system",
    keyring_path: str = "",
) -> Dict[str, Any]:
    """
    Creates an encrypted `.c404bak` backup bundle containing:
    1. Consistent SQLite database snapshot (via sqlite3.Connection.backup)
    2. All files in evidence_vault_storage/originals/
    3. Manifest JSON with SHA-256 checksums of every backed-up file
    """
    os.makedirs(backup_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    staging_db = os.path.join(backup_dir, f".staging_{ts}.db")

    # Online WAL-safe SQLite backup
    src_conn = sqlite3.connect(db_path)
    dst_conn = sqlite3.connect(staging_db)
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()

    manifest: Dict[str, Any] = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "initiated_by": initiated_by,
        "rpo_minutes": DEFAULT_RPO_MINUTES,
        "rto_minutes": DEFAULT_RTO_MINUTES,
        "files": {},
    }

    tar_buf = io.BytesIO()
    try:
        with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
            tar.add(staging_db, arcname="db/crime404_users.db")
            manifest["files"]["db/crime404_users.db"] = _sha256_file(staging_db)

            if os.path.exists(vault_originals_dir):
                for fname in sorted(os.listdir(vault_originals_dir)):
                    fpath = os.path.join(vault_originals_dir, fname)
                    if os.path.isfile(fpath):
                        arc = f"originals/{fname}"
                        tar.add(fpath, arcname=arc)
                        manifest["files"][arc] = _sha256_file(fpath)

            # The keyring is essential for recovery. It is included only inside the
            # encrypted backup envelope, never as a plaintext sidecar.
            if keyring_path and os.path.isfile(keyring_path):
                tar.add(keyring_path, arcname="keyring/keyring.json")
                manifest["files"]["keyring/keyring.json"] = _sha256_file(keyring_path)

            manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest_bytes)
            tar.addfile(info, io.BytesIO(manifest_bytes))
    finally:
        if os.path.exists(staging_db):
            os.remove(staging_db)

    plaintext_tar = tar_buf.getvalue()
    bundle_sha256 = hashlib.sha256(plaintext_tar).hexdigest()
    env = encrypt_bytes_envelope(plaintext_tar, key_manager, aad=b"crime404-backup-v1")

    backup_filename = f"crime404_backup_{ts}.c404bak"
    backup_path = os.path.join(backup_dir, backup_filename)
    envelope_record = {
        "format": "CRIME404-BAK-V1",
        "created_at_utc": manifest["created_at_utc"],
        "key_version": env["key_version"],
        "wrapped_dek": env["wrapped_dek"],
        "plaintext_sha256": bundle_sha256,
        "file_count": len(manifest["files"]),
    }
    meta_path = backup_path + ".meta.json"
    with open(backup_path, "wb") as bf:
        bf.write(env["ciphertext"])
    with open(meta_path, "w", encoding="utf-8") as mf:
        json.dump(envelope_record, mf, indent=2)

    return {
        "backup_filename": backup_filename,
        "backup_path": backup_path,
        "meta_path": meta_path,
        "plaintext_sha256": bundle_sha256,
        "size_bytes": len(env["ciphertext"]),
        "file_count": len(manifest["files"]),
        "rpo_minutes": DEFAULT_RPO_MINUTES,
        "rto_minutes": DEFAULT_RTO_MINUTES,
    }


def restore_and_verify_backup(
    backup_path: str,
    restore_dir: str,
    key_manager: KeyManager,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Decrypts a `.c404bak` bundle into `restore_dir`, verifies the bundle SHA-256 and
    every extracted file's SHA-256 against `manifest.json`.
    """
    meta_path = backup_path + ".meta.json"
    if not os.path.exists(backup_path) or not os.path.exists(meta_path):
        return False, {"error": "Backup file or metadata sidecar missing."}

    with open(meta_path, "r", encoding="utf-8") as mf:
        meta = json.load(mf)
    with open(backup_path, "rb") as bf:
        ciphertext = bf.read()

    plaintext_tar = decrypt_bytes_envelope(
        ciphertext, meta["wrapped_dek"], meta["key_version"], key_manager, aad=b"crime404-backup-v1"
    )
    if hashlib.sha256(plaintext_tar).hexdigest() != meta["plaintext_sha256"]:
        return False, {"error": "Backup bundle SHA-256 verification failed."}

    os.makedirs(restore_dir, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(plaintext_tar), mode="r:gz") as tar:
        # Safe extraction (prevent path traversal)
        for member in tar.getmembers():
            normalized = os.path.normpath(member.name)
            if os.path.isabs(member.name) or normalized == ".." or normalized.startswith(".." + os.sep):
                return False, {"error": f"Unsafe path in backup archive: {member.name}"}
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                return False, {"error": f"Unsupported special archive entry: {member.name}"}
        # The data filter additionally rejects links and unsafe ownership/mode metadata.
        tar.extractall(restore_dir, filter="data")

    manifest_path = os.path.join(restore_dir, "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    verified_files = 0
    mismatches = []
    for rel_path, expected_hash in manifest.get("files", {}).items():
        full_p = os.path.join(restore_dir, rel_path)
        if not os.path.exists(full_p):
            mismatches.append(f"Missing: {rel_path}")
        elif _sha256_file(full_p) != expected_hash:
            mismatches.append(f"Hash mismatch: {rel_path}")
        else:
            verified_files += 1

    if mismatches:
        return False, {"error": "Post-restore verification failed", "mismatches": mismatches}

    return True, {
        "verified_files": verified_files,
        "created_at_utc": manifest.get("created_at_utc"),
        "restored_db": os.path.join(restore_dir, "db", "crime404_users.db"),
        "restored_originals": os.path.join(restore_dir, "originals"),
        "restored_keyring": os.path.join(restore_dir, "keyring", "keyring.json"),
    }


def prune_old_backups(backup_dir: str, keep_last: int = 10) -> int:
    """Retains the newest `keep_last` .c404bak bundles and removes older ones."""
    if not os.path.exists(backup_dir) or keep_last < 1:
        return 0
    baks = sorted(
        [f for f in os.listdir(backup_dir) if f.endswith(".c404bak")],
        reverse=True,
    )
    removed = 0
    for old_f in baks[keep_last:]:
        for target in (os.path.join(backup_dir, old_f), os.path.join(backup_dir, old_f + ".meta.json")):
            if os.path.exists(target):
                os.remove(target)
        removed += 1
    return removed
