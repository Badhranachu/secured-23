from apps.surface_scan.services.result_utils import clean_text, status_payload

HEADER_RULES = [
    {
        "name": "content-security-policy",
        "expected_value": "A restrictive Content-Security-Policy without unsafe-inline, unsafe-eval, or wildcard defaults",
        "recommendation": "Add a restrictive Content-Security-Policy to reduce XSS and script-injection risk.",
    },
    {
        "name": "strict-transport-security",
        "expected_value": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "recommendation": "Add HSTS on HTTPS responses so browsers remember to use secure connections.",
    },
    {
        "name": "x-frame-options",
        "expected_value": "X-Frame-Options: DENY or SAMEORIGIN",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN to reduce clickjacking risk.",
    },
    {
        "name": "x-content-type-options",
        "expected_value": "X-Content-Type-Options: nosniff",
        "recommendation": "Set X-Content-Type-Options to nosniff to stop MIME sniffing.",
    },
    {
        "name": "referrer-policy",
        "expected_value": "Referrer-Policy: strict-origin-when-cross-origin or stricter",
        "recommendation": "Set Referrer-Policy to limit the amount of URL data leaked to third parties.",
    },
    {
        "name": "permissions-policy",
        "expected_value": "Permissions-Policy with only required browser features enabled",
        "recommendation": "Use Permissions-Policy to explicitly disable browser features you do not need.",
    },
]



def _normalize_headers(headers):
    return {str(key).lower(): clean_text(value) for key, value in (headers or {}).items()}



def _evaluate_header(name, value, https_reachable):
    status = "success"
    classification = "acceptable"
    message = f"{name} is present."

    if name == "content-security-policy":
        if not value:
            status, classification, message = "not_found", "missing", "No CSP header was returned."
        elif any(token in value.lower() for token in ["unsafe-inline", "unsafe-eval"]) or "*" in value:
            status, classification, message = "partial", "weak", "CSP exists but includes broad directives."
    elif name == "strict-transport-security":
        if https_reachable and not value:
            status, classification, message = "not_found", "missing", "No HSTS header was returned on HTTPS."
        elif not https_reachable and not value:
            status, classification, message = "not_available", "missing", "HTTPS is not available, so HSTS is not enforced."
        elif value:
            max_age = 0
            for chunk in value.lower().split(";"):
                if "max-age" in chunk and "=" in chunk:
                    try:
                        max_age = int(chunk.split("=", 1)[1].strip())
                    except Exception:
                        max_age = 0
            if max_age < 15552000:
                status, classification, message = "partial", "weak", "HSTS is present but shorter than a typical long-lived policy."
    elif name == "x-frame-options":
        if not value:
            status, classification, message = "not_found", "missing", "X-Frame-Options is missing."
        elif value.lower() not in {"deny", "sameorigin"}:
            status, classification, message = "partial", "weak", "X-Frame-Options is present but not using a strong value."
    elif name == "x-content-type-options":
        if not value:
            status, classification, message = "not_found", "missing", "X-Content-Type-Options is missing."
        elif value.lower() != "nosniff":
            status, classification, message = "partial", "weak", "X-Content-Type-Options is present but not set to nosniff."
    elif name == "referrer-policy":
        strong_referrers = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
        if not value:
            status, classification, message = "not_found", "missing", "Referrer-Policy is missing."
        elif value.lower() not in strong_referrers:
            status, classification, message = "partial", "weak", "Referrer-Policy exists but could be tightened."
    elif name == "permissions-policy":
        if not value:
            status, classification, message = "not_found", "missing", "Permissions-Policy is not present."
        elif value.strip() == "*":
            status, classification, message = "partial", "weak", "Permissions-Policy is present but too broad."

    return {
        "name": name,
        "status": status,
        "classification": classification,
        "value": value or None,
        "observed_value": value or "header absent",
        "message": message,
    }



def evaluate_security_headers(headers, https_reachable=False):
    normalized = _normalize_headers(headers)
    if not normalized and not https_reachable:
        return status_payload(
            "not_available",
            evaluations=[],
            summary={"missing_count": 0, "weak_count": 0, "acceptable_count": 0},
            error_message="No response headers were available for evaluation.",
        )

    evaluations = []
    for rule in HEADER_RULES:
        item = _evaluate_header(rule["name"], normalized.get(rule["name"], ""), https_reachable)
        item.update(
            {
                "expected_value": rule["expected_value"],
                "recommendation": rule["recommendation"],
                "evidence_source": "https response headers" if https_reachable else "http response headers",
            }
        )
        evaluations.append(item)

    missing_count = len([item for item in evaluations if item["classification"] == "missing"])
    weak_count = len([item for item in evaluations if item["classification"] == "weak"])
    acceptable_count = len([item for item in evaluations if item["classification"] == "acceptable"])
    module_status = "success" if not missing_count and not weak_count else "partial"

    return status_payload(
        module_status,
        evaluated_headers=evaluations,
        evaluations=evaluations,
        summary={
            "missing_count": missing_count,
            "weak_count": weak_count,
            "acceptable_count": acceptable_count,
        },
        missing_headers=[item["name"] for item in evaluations if item["classification"] == "missing"],
    )
