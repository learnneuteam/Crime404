"""
CRIME404 Enterprise Verification Test Suite (Checklist Section 11)
Covers:
A. Authentication, Argon2id/scrypt, Compromised Passwords, TOTP MFA, Recovery Codes, Throttling
B. RBAC, Case-Level Isolation, Multi-Tenancy, Self-Privilege Escalation Prevention
C. Encryption at Rest (AES-256-GCM), Key Separation & Key Rotation
D. Evidence Vault Content Validation (Executable Rejection), Encrypted Originals, Working Copies, SHA-256
E. Tamper-Evident Hash-Chained Audit Log & Tamper Detection
F. Encrypted Backup & Post-Restore Hash Verification
"""

import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from security.auth import (
    validate_password_strength,
    hash_password,
    verify_password,
    generate_totp_secret,
    verify_totp,
    _hotp,
    generate_recovery_codes,
    verify_and_consume_recovery_code,
    LoginThrottle,
)
from security.rbac import check_user_case_permission, can_modify_user_role
from security.crypto import (
    KeyManager,
    encrypt_bytes_envelope,
    decrypt_bytes_envelope,
    encrypt_text_field,
    decrypt_text_field,
)
from security.audit import compute_audit_entry_hash, verify_audit_chain, redact_dict
from forensics.vault import EvidenceVault, validate_evidence_content
from services.backup import create_encrypted_backup, restore_and_verify_backup


class TestEnterpriseAuthAndMFA(unittest.TestCase):
    def test_password_policy_and_hashing(self):
        ok, _ = validate_password_strength("short")
        self.assertFalse(ok)
        ok, _ = validate_password_strength("password1234")  # compromised list
        self.assertFalse(ok)
        ok, _ = validate_password_strength("CorrectHorseBatteryStaple99", username="dabs")
        self.assertTrue(ok)

        h1 = hash_password("CorrectHorseBatteryStaple99")
        h2 = hash_password("CorrectHorseBatteryStaple99")
        self.assertNotEqual(h1, h2)  # unique salt
        valid, _ = verify_password(h1, "CorrectHorseBatteryStaple99")
        self.assertTrue(valid)
        bad, _ = verify_password(h1, "WrongPassphrase1234")
        self.assertFalse(bad)

    def test_totp_mfa_and_recovery_codes(self):
        secret = generate_totp_secret()
        now = 1700000000
        code = _hotp(secret, now // 30)
        self.assertTrue(verify_totp(secret, code, now_ts=now))
        self.assertFalse(verify_totp(secret, "000000", now_ts=now))

        plain, hashed = generate_recovery_codes(4)
        ok, rem = verify_and_consume_recovery_code(plain[0], hashed)
        self.assertTrue(ok)
        self.assertEqual(len(rem), 3)
        # Single-use: reusing the same recovery code must fail
        ok2, _ = verify_and_consume_recovery_code(plain[0], rem)
        self.assertFalse(ok2)

    def test_login_throttle_lockout(self):
        throttle = LoginThrottle(max_attempts=3, window_seconds=60, lockout_seconds=300)
        for _ in range(3):
            throttle.record_failure("alice", "10.0.0.5", now=1000.0)
        blocked, wait_s = throttle.is_blocked("alice", "10.0.0.5", now=1010.0)
        self.assertTrue(blocked)
        self.assertGreater(wait_s, 0)
        throttle.record_success("alice", "10.0.0.5")
        blocked_after, _ = throttle.is_blocked("alice", "10.0.0.5", now=1011.0)
        self.assertFalse(blocked_after)


class TestRBACAndMultiTenancy(unittest.TestCase):
    def test_case_isolation_between_investigators(self):
        inv1 = SimpleNamespace(id=1, role="investigator", org_id=1, is_active=True)
        inv2 = SimpleNamespace(id=2, role="investigator", org_id=1, is_active=True)
        case1 = SimpleNamespace(id=10, user_id=1, org_id=1)
        case2 = SimpleNamespace(id=20, user_id=2, org_id=1)

        self.assertTrue(check_user_case_permission(inv1, case1, "case:read")[0])
        self.assertFalse(check_user_case_permission(inv1, case2, "case:read")[0])
        self.assertFalse(check_user_case_permission(inv2, case1, "evidence:upload")[0])

    def test_cross_org_and_auditor_and_self_escalation(self):
        admin_org1 = SimpleNamespace(id=1, role="system_admin", org_id=1, is_active=True)
        case_org2 = SimpleNamespace(id=99, user_id=5, org_id=2)
        self.assertFalse(check_user_case_permission(admin_org1, case_org2, "case:read")[0])

        auditor = SimpleNamespace(id=3, role="read_only_auditor", org_id=1, is_active=True)
        case1 = SimpleNamespace(id=10, user_id=1, org_id=1)
        membership = SimpleNamespace(is_active=True, role_override=None)
        self.assertTrue(check_user_case_permission(auditor, case1, "case:read", membership)[0])
        self.assertFalse(check_user_case_permission(auditor, case1, "evidence:upload", membership)[0])

        # Prevent self-privilege modification
        self.assertFalse(can_modify_user_role(admin_org1, 1, "lead_investigator")[0])
        self.assertTrue(can_modify_user_role(admin_org1, 2, "lead_investigator")[0])


class TestCryptoVaultAuditAndBackup(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="crime404_test_")
        self.km = KeyManager(key_store_dir=os.path.join(self.tmpdir, "keys"))
        self.vault = EvidenceVault(os.path.join(self.tmpdir, "vault"), self.km)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_envelope_encryption_and_key_rotation(self):
        env = encrypt_bytes_envelope(b"secret forensic log", self.km, aad=b"case1")
        self.assertEqual(env["key_version"], "v1")
        new_ver = self.km.rotate_master_key()
        self.assertEqual(new_ver, "v2")
        # Old v1 ciphertext still decrypts after rotation
        pt = decrypt_bytes_envelope(env["ciphertext"], env["wrapped_dek"], env["key_version"], self.km, aad=b"case1")
        self.assertEqual(pt, b"secret forensic log")

        enc_str = encrypt_text_field("JBSWY3DPEHPK3PXP", self.km)
        self.assertTrue(enc_str.startswith("ENC:"))
        self.assertEqual(decrypt_text_field(enc_str, self.km), "JBSWY3DPEHPK3PXP")

    def test_vault_rejects_executables_and_preserves_encrypted_originals(self):
        ok_exe, _ = validate_evidence_content(b"MZ\x90\x00fake_pe_binary", ".log")
        self.assertFalse(ok_exe)
        ok_zip, _ = validate_evidence_content(b"PK\x03\x04fake_zip", ".txt")
        self.assertFalse(ok_zip)

        sample_log = b"2026-11-18T10:00:00Z INFO user=alice ip=192.168.1.10 login success\n"
        ok_log, _ = validate_evidence_content(sample_log, ".log")
        self.assertTrue(ok_log)

        meta = self.vault.store_original(sample_log, "EV-1-101", "auth.log", case_id=1)
        art = SimpleNamespace(
            case_id=1,
            artifact_code="EV-1-101",
            original_filename="auth.log",
            stored_path=meta["stored_path"],
            sha256_hash=meta["sha256_hash"],
            wrapped_dek=meta["wrapped_dek"],
            key_version=meta["key_version"],
            is_encrypted=True,
        )
        work_path, intact, _ = self.vault.create_working_copy(art)
        self.assertTrue(intact)
        self.assertTrue(os.path.exists(work_path))
        with open(work_path, "rb") as f:
            self.assertEqual(f.read(), sample_log)

    def test_tamper_evident_audit_chain(self):
        redacted = redact_dict({"username": "alice", "password": "secret", "mfa_code": "123456"})
        self.assertEqual(redacted["password"], "[REDACTED]")
        self.assertEqual(redacted["mfa_code"], "[REDACTED]")

        h1 = compute_audit_entry_hash("0" * 64, "2026-11-19T00:00:00Z", 1, 1, "alice", "LOGIN_SUCCESS", "user", "1", "SUCCESS", "", "{}")
        r1 = SimpleNamespace(id=1, prev_hash="0" * 64, timestamp_utc="2026-11-19T00:00:00Z", org_id=1, user_id=1, username="alice", action="LOGIN_SUCCESS", target_type="user", target_id="1", outcome="SUCCESS", reason="", details_json="{}", entry_hash=h1)
        h2 = compute_audit_entry_hash(h1, "2026-11-19T00:01:00Z", 1, 1, "alice", "EVIDENCE_UPLOADED", "artifact", "EV-1", "SUCCESS", "", "{}")
        r2 = SimpleNamespace(id=2, prev_hash=h1, timestamp_utc="2026-11-19T00:01:00Z", org_id=1, user_id=1, username="alice", action="EVIDENCE_UPLOADED", target_type="artifact", target_id="EV-1", outcome="SUCCESS", reason="", details_json="{}", entry_hash=h2)

        valid, _, _ = verify_audit_chain([r1, r2])
        self.assertTrue(valid)

        # Simulate tampering with row 1
        r1.action = "ADMIN_GRANTED"
        valid_tampered, broken_id, _ = verify_audit_chain([r1, r2])
        self.assertFalse(valid_tampered)
        self.assertEqual(broken_id, 1)

    def test_encrypted_backup_and_restore_verification(self):
        db_path = os.path.join(self.tmpdir, "test.db")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)")
        conn.execute("INSERT INTO t (val) VALUES ('forensic_record')")
        conn.commit()
        conn.close()

        self.vault.store_original(b"log line 1\n", "EV-1-101", "ev.log", case_id=1)
        backup_dir = os.path.join(self.tmpdir, "backups")
        res = create_encrypted_backup(db_path, self.vault.originals_dir, backup_dir, self.km, initiated_by="admin")
        self.assertTrue(os.path.exists(res["backup_path"]))

        restore_dir = os.path.join(self.tmpdir, "restored")
        ok, info = restore_and_verify_backup(res["backup_path"], restore_dir, self.km)
        self.assertTrue(ok)
        self.assertEqual(info["verified_files"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
