import base64
import json
from datetime import datetime, timezone

from .helpers import build_finding


def _decode_segment(segment):
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode((segment + padding).encode("utf-8")).decode("utf-8"))


def inspect_jwt_token(token):
    findings = []
    metadata = {"present": bool(token)}
    if not token:
        return {"findings": findings, "metadata": metadata}

    try:
        header_segment, payload_segment, _signature = token.split(".", 2)
        header = _decode_segment(header_segment)
        payload = _decode_segment(payload_segment)
        metadata["header"] = header
        metadata["payload"] = payload
    except Exception as exc:
        findings.append(build_finding("jwt_token", "critical", "JWT token could not be decoded", f"The configured token does not look like a valid JWT: {exc}", recommendation="Verify the token format before using it for API authorization checks."))
        return {"findings": findings, "metadata": metadata}

    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        findings.append(build_finding("jwt_token", "critical", "Unsigned JWT algorithm detected", "The token header advertises alg=none.", recommendation="Reject unsigned JWTs and enforce a strong signing algorithm."))

    exp = payload.get("exp")
    if exp is None:
        findings.append(build_finding("jwt_token", "warning", "JWT token has no expiry claim", "The token payload does not contain an exp claim.", recommendation="Issue short-lived access tokens and require refresh rotation."))
    else:
        expires_at = datetime.fromtimestamp(int(exp), tz=timezone.utc)
        metadata["expires_at"] = expires_at.isoformat()
        if expires_at <= datetime.now(timezone.utc):
            findings.append(build_finding("jwt_token", "critical", "Expired JWT provided", "The stored JWT or bearer token is already expired.", recommendation="Refresh the token before attempting protected-route authorization checks."))

    if "iss" not in payload:
        findings.append(build_finding("jwt_token", "info", "JWT missing issuer claim", "The decoded JWT payload does not include an iss claim.", recommendation="Include standard issuer/audience claims to strengthen token validation."))
    return {"findings": findings, "metadata": metadata}
