from .helpers import build_finding, safe_request

PROTECTED_HINTS = ["admin", "profile", "account", "settings", "me", "dashboard", "users"]
EXISTS_STATUSES = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405}


def _safe_probe_method(method):
    return method if method in {"GET", "HEAD", "OPTIONS"} else "OPTIONS"


def _classify_result(result):
    status = result.get("unauth_status")
    if status in EXISTS_STATUSES:
        return "working"
    if status == 404:
        return "missing"
    if status is None:
        return "unreachable"
    return "unknown"


def scan_api_endpoints(project, normalized_endpoints, auth_context=None):
    findings = []
    endpoint_results = []
    auth_token = (auth_context or {}).get("token") or project.get_token()

    for endpoint in normalized_endpoints:
        request_method = _safe_probe_method(endpoint.method)
        base_headers = {"Accept": "application/json", "Origin": "http://localhost:5173"}
        unauth_response, unauth_error = safe_request(request_method, endpoint.url, headers=base_headers, timeout=8)
        auth_response, auth_error = (None, None)
        if auth_token:
            auth_headers = dict(base_headers)
            auth_headers["Authorization"] = f"Bearer {auth_token}"
            auth_response, auth_error = safe_request(request_method, endpoint.url, headers=auth_headers, timeout=8)

        result = {
            "route": endpoint.route,
            "declared_method": endpoint.method,
            "probe_method": request_method,
            "url": endpoint.url,
            "unauth_status": unauth_response.status_code if unauth_response else None,
            "auth_status": auth_response.status_code if auth_response else None,
            "unauth_error": unauth_error,
            "auth_error": auth_error,
            "auth_required": (unauth_response.status_code if unauth_response else None) in {401, 403},
        }
        result["classification"] = _classify_result(result)
        endpoint_results.append(result)

        if unauth_response is None:
            findings.append(build_finding("api_endpoints", "warning", "API endpoint unreachable", f"AEGIS AI could not safely reach {endpoint.url}.", endpoint=endpoint.url, recommendation="Verify the API base URL and whether the service is running."))
            continue

        lower_route = endpoint.route.lower()
        protected_hint = any(keyword in lower_route for keyword in PROTECTED_HINTS)
        if protected_hint and unauth_response.status_code < 300:
            findings.append(build_finding("api_endpoints", "critical" if "admin" in lower_route else "warning", "Potential protected endpoint exposed without auth", f"The route {endpoint.route} responded with {unauth_response.status_code} without authentication.", endpoint=endpoint.url, recommendation="Require authentication and enforce role checks before serving this endpoint."))

        if auth_response is not None and "admin" in lower_route and auth_response.status_code < 300:
            findings.append(build_finding("api_endpoints", "critical", "User token reached an admin-like route", f"The supplied token was accepted by {endpoint.route}, which looks like an admin route.", endpoint=endpoint.url, recommendation="Re-check RBAC and object-level authorization on admin APIs."))

        response_headers = {key.lower(): value for key, value in unauth_response.headers.items()}
        if response_headers.get("access-control-allow-origin") == "*" and (result["auth_required"] or protected_hint):
            findings.append(build_finding("api_endpoints", "warning", "Permissive CORS on sensitive endpoint", f"The endpoint {endpoint.route} returned Access-Control-Allow-Origin: *.", endpoint=endpoint.url, recommendation="Restrict CORS origins for authenticated or administrative routes."))

        if "set-cookie" in response_headers and "httponly" not in response_headers["set-cookie"].lower():
            findings.append(build_finding("api_endpoints", "warning", "Cookie missing HttpOnly flag", "A Set-Cookie header was observed without an obvious HttpOnly flag.", endpoint=endpoint.url, recommendation="Mark session cookies as HttpOnly and Secure where possible."))

    working_endpoints = [item for item in endpoint_results if item["classification"] == "working"]
    protected_endpoints = [item for item in working_endpoints if item["auth_required"]]
    public_endpoints = [item for item in working_endpoints if not item["auth_required"]]
    admin_accessible_with_token = [item for item in endpoint_results if "admin" in item["route"].lower() and item.get("auth_status") and item["auth_status"] < 300]

    return {
        "findings": findings,
        "metadata": {
            "endpoint_results": endpoint_results,
            "count": len(endpoint_results),
            "working_count": len(working_endpoints),
            "public_count": len(public_endpoints),
            "protected_count": len(protected_endpoints),
            "admin_accessible_with_token_count": len(admin_accessible_with_token),
            "working_endpoints": working_endpoints,
            "public_endpoints": public_endpoints,
            "protected_endpoints": protected_endpoints,
            "admin_accessible_with_token": admin_accessible_with_token,
        },
    }
