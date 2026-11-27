"""Regression tests for CRIME404's integrated evidence and recovery hardening."""
import json
import os
import sqlite3
import tempfile
import unittest

from security.crypto import KeyManager
from forensics.vault import EvidenceVault
from services.backup import create_encrypted_backup, restore_and_verify_backup


class TestIntegratedVaultAndRecovery(unittest.TestCase):
    def test_encrypted_backup_contains_keyring_and_originals(self):
        with tempfile.TemporaryDirectory(prefix="crime404_hardening_") as root:
            key_dir = os.path.join(root, "keys")
            vault_dir = os.path.join(root, "vault")
            originals = os.path.join(vault_dir, "originals")
            backup_dir = os.path.join(root, "backups")
            os.makedirs(originals)
            km = KeyManager(key_store_dir=key_dir)
            vault = EvidenceVault(vault_dir, km)
            sample = b"2026-11-22T10:00:00Z user=analyst login success\n"
            stored = vault.store_original(sample, "EV-1-101", "auth.log", 1)
            self.assertTrue(os.path.exists(stored["stored_path"]))
            db_path = os.path.join(root, "crime404.db")
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE marker (value TEXT)")
            conn.execute("INSERT INTO marker VALUES ('ok')")
            conn.commit(); conn.close()

            result = create_encrypted_backup(
                db_path, originals, backup_dir, km,
                initiated_by="test", keyring_path=os.path.join(key_dir, "keyring.json")
            )
            self.assertTrue(os.path.exists(result["backup_path"]))
            restore_dir = os.path.join(root, "restore")
            ok, restored = restore_and_verify_backup(result["backup_path"], restore_dir, km)
            self.assertTrue(ok, restored)
            self.assertTrue(os.path.exists(restored["restored_keyring"]))
            self.assertTrue(os.path.exists(os.path.join(restored["restored_originals"], os.path.basename(stored["stored_path"]))))


if __name__ == "__main__":
    unittest.main()
