# CRIME404 Biometric Integration — Phases 1–3

This patch replaces the handwritten WebAuthn checks and connects two distinct verification paths to Flask:

1. **Platform passkey (WebAuthn/FIDO2):** the operating system's authenticator performs user verification. Depending on the device, it may use Touch ID, Face ID, Windows Hello, a device PIN, or another supported method. CRIME404 must not label this as definitely fingerprint verification.
2. **Separate face matching:** the browser captures face samples after an explicit consent prompt. The Flask service computes face encodings in memory and stores only an AES-256-GCM-encrypted numeric template. Submitted source images are not written to disk or retained in the database.

## Install

```bash
pip install -r requirements.txt
pip install -r requirements-biometric.txt
```

`face-recognition` depends on `dlib`. On macOS, installation may require Xcode Command Line Tools, CMake, and a compatible Python version. If the optional face package cannot load, face endpoints fail closed with an installation message; the rest of Flask can still start.

## WebAuthn configuration

Set these environment variables for the exact URL used by the browser:

```bash
WEBAUTHN_RP_ID=localhost
WEBAUTHN_ORIGIN=http://localhost:5000
WEBAUTHN_RP_NAME=CRIME404 Digital Forensics
```

For deployment, use your real domain and HTTPS, for example `WEBAUTHN_RP_ID=crime404.example.org` and `WEBAUTHN_ORIGIN=https://crime404.example.org`. The origin host must match the RP ID. Do not use a changing host, raw LAN IP, or an untrusted reverse-proxy header for WebAuthn.

Camera capture requires HTTPS or localhost. The app's Permissions-Policy now allows same-origin camera access only; microphone and geolocation remain disabled.

## Enrolment workflow

1. Create an account and sign in normally.
2. Open **My Profile → Investigator Identity Verification**.
3. Register a **Device Passkey**. The operating system controls the available user-verification method. CRIME404 receives a signed assertion and public credential information, never the fingerprint/Face ID data.
4. Separately choose **Enrol Face Verification**. Read the consent prompt, allow camera access, and capture 5 samples with one face in frame.
5. The server computes face encodings and stores only an encrypted average template. To remove it, use **Remove Face Template**.

## Protected operations

- Existing operations that request the `fingerprint` gate now require a registered, verified platform passkey.
- Existing operations that request the `face` gate now require an enrolled face template and a fresh face match.
- Verification freshness uses the existing `REAUTH_TTL_MINUTES` setting.
- An account with no required factor is denied the protected action (HTTP 428) rather than silently bypassing verification.

The current patch connects biometric step-up verification to the Flask session and protected operations. Password + existing MFA remains the initial login mechanism; this patch does **not** yet implement passwordless/passkey-first login.

## Important limitations

- WebAuthn reports cryptographic user verification, not whether the OS used a fingerprint, face, or PIN. The interface therefore calls it a **platform passkey**, not a guaranteed fingerprint scan.
- The face matcher is a demonstration-grade 1:1 face comparison. It does not implement robust presentation-attack detection/liveness detection. A face match alone must not be treated as proof of identity or used for real-world high-stakes decisions.
- Face recognition thresholds must be validated against a representative consented test set before any real deployment. The current conservative distance threshold is a starting point, not a calibrated accuracy claim.
- Use only consenting adult test participants and synthetic/demo accounts for the school demonstration. Do not enrol classmates or collect their face data without appropriate informed consent and supervision.
- Store the keyring outside the source repository, restrict file permissions, back it up securely, and never commit `.env`, keyring files, face templates, databases, or evidence to source control.

## Migration notes

`run_safe_migrations()` adds `sign_count` and `verified` to the existing WebAuthn credential table and creates the face-template table. Legacy credentials are intentionally left unverified (`verified=0`) because the old implementation did not validate full WebAuthn attestation, origin, RP ID, or UV flags. Users must re-register their platform passkey. Existing forensic case/evidence tables are not intentionally changed.

## Verification checklist

- [ ] Install both requirement files in a clean virtual environment.
- [ ] Set stable `SECRET_KEY`, `CRIME404_MASTER_KEY`, `WEBAUTHN_RP_ID`, and `WEBAUTHN_ORIGIN` values.
- [ ] Start Flask on `http://localhost:5000` for local testing, or HTTPS for a real hostname.
- [ ] Register a platform passkey and verify it appears in My Profile.
- [ ] Attempt a moderate protected action before passkey verification; it should request verification.
- [ ] Complete passkey verification; retry the action within the re-authentication window.
- [ ] Enrol face verification with explicit consent and verify that the face status appears.
- [ ] Attempt a critical protected action before face verification; it should request face verification.
- [ ] Complete face verification; retry the action.
- [ ] Test a non-matching face, camera denial, no-face frame, multiple-face frame, expired challenge, and deleted credential.
- [ ] Confirm audit events are recorded and no raw camera images are stored.
- [ ] Test on the actual Mac and browser intended for the expo; platform authenticator availability differs by device.

These changes have been syntax-checked, but a full Flask runtime and live camera/WebAuthn ceremony still need to be tested in the project's own installed environment and on the demonstration hardware.
