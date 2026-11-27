"""End-to-end tests for the current fail-closed CRIME404 Flask integration."""
import io
import json
import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import app as crime_app


@pytest.fixture
def client(tmp_path):
    # Use an isolated database engine for each test app context.
    crime_app.app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path / 'test_crime404.db'}"
    crime_app.app.config["TESTING"] = True
    with crime_app.app.app_context():
        try:
            crime_app.db.drop_all()
        except Exception:
            pass
        crime_app.db.create_all()
    with crime_app.app.test_client() as c:
        yield c


def get_csrf(client, path="/login"):
    response = client.get(path)
    html = response.data.decode("utf-8")
    marker = 'name="csrf-token" content="'
    assert marker in html, f"CSRF meta tag missing from {path}"
    return html.split(marker, 1)[1].split('"', 1)[0]


def test_full_end_to_end_synthetic_investigation(client):
    csrf = get_csrf(client, "/signup")
    response = client.post("/signup", data={
        "csrf_token": csrf,
        "username": "lead_investigator",
        "email": "lead@crime404.local",
        "password": "StrongPassword123!",
    }, follow_redirects=True)
    assert response.status_code == 200

    csrf = get_csrf(client, "/login")
    response = client.post("/login", data={
        "csrf_token": csrf,
        "username": "lead_investigator",
        "password": "StrongPassword123!",
    }, follow_redirects=True)
    assert response.status_code == 200

    forged = client.post("/api/cases", json={"title": "Forged Case"})
    assert forged.status_code == 403
    headers = {"X-CSRF-Token": get_csrf(client, "/")}

    # Descriptor-only enrollment is intentionally rejected; genuine camera images are required.
    face = client.post("/api/face/enroll", json={"descriptor": [0.1, 0.2, 0.3]}, headers=headers)
    assert face.status_code in (400, 503)

    auth_payload = json.dumps([
        {"timestamp": "2026-11-12T23:52:10+05:30", "src_ip": "10.0.4.22", "user": "admin", "message": "Failed password for user=admin from 10.0.4.22"},
        {"timestamp": "2026-11-12T23:53:05+05:30", "src_ip": "10.0.4.22", "user": "dev_ops", "message": "Accepted password for user=dev_ops from 10.0.4.22"},
        {"timestamp": "2026-11-12T23:56:40+05:30", "src_ip": "10.0.4.22", "user": "dev_ops", "process": "payload.ps1", "message": "sudo executed payload.ps1 by user=dev_ops"},
    ]).encode("utf-8")
    up1 = client.post("/api/upload", data={"file": (io.BytesIO(auth_payload), "auth_ist.json")}, headers=headers)
    assert up1.status_code == 200, up1.get_json()
    state1 = up1.get_json()["state"]
    assert len(state1["evidence"]) == 1
    assert len(state1["structured_hypotheses"]) >= 2

    egress_csv = (
        "timestamp,src_ip,dst_ip,user,file,message\n"
        "2026-11-12T18:44:20Z,10.0.4.22,185.220.101.4,dev_ops,payroll_backup.zip,Outbound transfer of payroll_backup.zip\n"
    ).encode("utf-8")
    up2 = client.post("/api/upload", data={"file": (io.BytesIO(egress_csv), "egress_utc.csv")}, headers=headers)
    assert up2.status_code == 200, up2.get_json()
    state2 = up2.get_json()["state"]
    assert state2["metrics"]["severity_score"] >= 50

    contra_log = b"2026-11-12T18:25:00Z Session terminated for user=dev_ops from 10.0.4.22\n"
    up3 = client.post("/api/upload", data={"file": (io.BytesIO(contra_log), "session_contradiction.log")}, headers=headers)
    assert up3.status_code == 200, up3.get_json()
    state3 = up3.get_json()["state"]
    assert any(g["gap_type"] == "Cross-Source Contradiction" for g in state3["structured_gaps"])

    contra_code = [a["artifact_code"] for a in state3["evidence"] if a["name"] == "session_contradiction.log"][0]
    deleted = client.delete(f"/api/evidence/{contra_code}", headers=headers)
    assert deleted.status_code == 200, deleted.get_json()
    state4 = deleted.get_json()["state"]
    assert not any(g["gap_type"] == "Cross-Source Contradiction" for g in state4["structured_gaps"])
    assert any("EVIDENCE_EXCLUDED" in log for log in state4["activity_logs"])
    assert any(a["artifact_code"] == contra_code and a["status"].startswith("Retired") for a in state4["evidence"])

    custody = client.get("/api/custody/verify", headers=headers)
    assert custody.status_code == 200
    audit = client.get("/api/audit/verify", headers=headers)
    assert audit.status_code == 200
    assert audit.get_json()["verified"] is True

    # Session revocation is POST + CSRF protected.
    logged_out = client.post("/logout", headers=headers)
    assert logged_out.status_code == 302
    assert client.get("/api/state").status_code == 401
