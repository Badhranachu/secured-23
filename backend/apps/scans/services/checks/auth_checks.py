from .helpers import build_finding, safe_request


def authenticate_test_account(project, normalized_endpoints):
    findings = []
    metadata = {
        "attempted": False,
        "login_url": None,
        "authenticated": False,
        "status": "not_available",
        "reason": "No test credentials were configured.",
    }
    email = project.test_email
    password = project.get_test_password()
    if not email or not password:
        return {"findings": findings, "metadata": metadata, "token": None}

    login_candidates = [endpoint for endpoint in normalized_endpoints if any(keyword in endpoint.route.lower() for keyword in ["login", "signin", "token"])]
    if not login_candidates and project.api_base_url:
        login_candidates = []
        for route in ["/login", "/api/login", "/auth/login", "/api/auth/login"]:
            login_candidates.append(type("Endpoint", (), {"url": project.api_base_url.rstrip("/") + route, "route": route, "method": "POST"})())

    if not login_candidates:
        metadata["reason"] = "No login-style routes were discovered for the test account flow."
        return {"findings": findings, "metadata": metadata, "token": None}

    payloads = [
        {"email": email, "password": password},
        {"username": email, "password": password},
        {"login": email, "password": password},
    ]

    token = None
    try:
        for candidate in login_candidates[:4]:
            metadata["attempted"] = True
            metadata["status"] = "partial"
            metadata["reason"] = "A login route was discovered, but the provided test account did not yield a token yet."
            metadata["login_url"] = candidate.url
            for payload in payloads:
                response, _error = safe_request("POST", candidate.url, json=payload, timeout=8)
                if response is None:
                    continue
                metadata["login_status"] = response.status_code
                if response.status_code not in {200, 201}:
                    continue
                try:
                    data = response.json()
                except Exception:
                    data = {}
                token = data.get("access") or data.get("token") or data.get("jwt") or data.get("access_token") or (data.get("data") or {}).get("token")
                if token:
                    metadata["authenticated"] = True
                    metadata["status"] = "success"
                    metadata["reason"] = "The test account login returned a bearer token."
                    break
            if token:
                break
    finally:
        del password

    if metadata["attempted"] and not metadata["authenticated"]:
        findings.append(build_finding("auth_checks", "warning", "Test account authentication did not succeed", "A login attempt was made with the configured test account but no bearer token was obtained.", endpoint=metadata.get("login_url") or "", recommendation="Verify the login endpoint route, payload shape, and whether MFA or CSRF is required."))

    return {"findings": findings, "metadata": metadata, "token": token}
