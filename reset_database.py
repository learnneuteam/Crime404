"""
CRIME404 Clean Database & Vault Reset Utility
Deletes all SQLite database files (including WAL/SHM), isolated keys, audit logs,
backups, and vault storage so you can start completely fresh.
"""

import os
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TARGET_FILES = [
    os.path.join(BASE_DIR, "instance", "crime404_users.db"),
    os.path.join(BASE_DIR, "instance", "crime404_users.db-wal"),
    os.path.join(BASE_DIR, "instance", "crime404_users.db-shm"),
]

TARGET_DIRS = [
    os.path.join(BASE_DIR, "keys_isolated"),
    os.path.join(BASE_DIR, "logs_isolated"),
    os.path.join(BASE_DIR, "backups_isolated"),
    os.path.join(BASE_DIR, "evidence_vault_storage", "originals"),
    os.path.join(BASE_DIR, "evidence_vault_storage", "working"),
    os.path.join(BASE_DIR, "evidence_vault_storage", "quarantine"),
]


def main():
    for fp in TARGET_FILES:
        if os.path.exists(fp):
            os.remove(fp)
            print("Removed:", fp)

    for dp in TARGET_DIRS:
        if os.path.exists(dp):
            for root, dirs, files in os.walk(dp, topdown=False):
                for fn in files:
                    p = os.path.join(root, fn)
                    try:
                        os.chmod(p, 0o600)
                    except OSError:
                        pass
                    os.remove(p)
                for dn in dirs:
                    shutil.rmtree(os.path.join(root, dn), ignore_errors=True)
            print("Cleared:", dp)

    # Re-initialize empty schema
    from app import app, db, run_safe_migrations
    with app.app_context():
        run_safe_migrations()
    print("Clean database initialized. You can now run: python3 app.py")


if __name__ == "__main__":
    main()
