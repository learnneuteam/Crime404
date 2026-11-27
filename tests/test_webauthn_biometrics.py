"""WebAuthn option and malformed-response tests for the current helper signatures."""
import json
import os
import sys
import unittest
from types import SimpleNamespace

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from security.webauthn import (
    authentication_options, b64url_decode, b64url_encode,
    options_to_json, registration_options, verify_authentication,
    verify_registration,
)


class TestWebAuthnBiometrics(unittest.TestCase):
    def setUp(self):
        self.request = SimpleNamespace(
            host="localhost:5000", host_url="http://localhost:5000/",
            scheme="http", headers={},
        )

    def test_registration_and_authentication_options(self):
        reg_opts, reg_json_text = registration_options(self.request, user_id=1, username="investigator1", existing_ids=())
        reg_json = json.loads(reg_json_text)
        self.assertIn("challenge", reg_json)
        self.assertEqual(reg_json["user"]["name"], "investigator1")
        raw_chal = b64url_decode(reg_json["challenge"])
        self.assertGreaterEqual(len(raw_chal), 16)
        self.assertEqual(b64url_encode(raw_chal), reg_json["challenge"])
        auth_opts, auth_json_text = authentication_options(self.request, credential_ids=[b64url_encode(raw_chal)])
        auth_json = json.loads(auth_json_text)
        self.assertIn("challenge", auth_json)
        self.assertEqual(len(auth_json["allowCredentials"]), 1)

    def test_rejects_malformed_responses(self):
        with self.assertRaises(Exception):
            verify_registration(self.request, {}, b"invalid-challenge")
        with self.assertRaises(Exception):
            verify_authentication(self.request, {}, b"invalid-challenge", b"invalid-key", 0)


if __name__ == "__main__":
    unittest.main()
