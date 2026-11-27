"""WebAuthn / FIDO2 helper module supporting both device and cross-device phone passkeys."""

import os
from urllib.parse import urlparse

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


def b64url_encode(data: bytes) -> str:
    return bytes_to_base64url(data)


def b64url_decode(val: str) -> bytes:
    return base64url_to_bytes(val)


def resolve_rp(request):
    rp_id = os.environ.get("WEBAUTHN_RP_ID")
    origin = os.environ.get("WEBAUTHN_ORIGIN")
    if rp_id and origin:
        return rp_id, origin

    host = (request.host or "localhost:5000").split(":")[0]
    if host == "127.0.0.1":
        host = "localhost"
    scheme = "https" if request.is_secure else "http"
    port = request.host.split(":")[1] if ":" in (request.host or "") else ""
    resolved_origin = f"{scheme}://{host}{(':' + port) if port else ''}"
    return host, resolved_origin


def registration_options(request, user_id: int, username: str, existing_ids: list):
    rp_id, _ = resolve_rp(request)
    exclude = [PublicKeyCredentialDescriptor(id=b64url_decode(cid)) for cid in existing_ids if cid]
    opts = generate_registration_options(
        rp_id=rp_id,
        rp_name="CRIME404 Forensic System",
        user_id=str(user_id).encode("utf-8"),
        user_name=username,
        user_display_name=username,
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    return opts, options_to_json(opts)


def verify_registration(request, credential_json, expected_challenge: bytes):
    rp_id, origin = resolve_rp(request)
    return verify_registration_response(
        credential=credential_json,
        expected_challenge=expected_challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        require_user_verification=False,
    )


def authentication_options(request, allowed_ids: list):
    rp_id, _ = resolve_rp(request)
    allow = [PublicKeyCredentialDescriptor(id=b64url_decode(cid)) for cid in allowed_ids if cid]
    opts = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return opts, options_to_json(opts)


def verify_authentication(request, credential_json, expected_challenge: bytes, credential_public_key: bytes, current_sign_count: int):
    rp_id, origin = resolve_rp(request)
    return verify_authentication_response(
        credential=credential_json,
        expected_challenge=expected_challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=credential_public_key,
        credential_current_sign_count=current_sign_count,
        require_user_verification=False,
    )
