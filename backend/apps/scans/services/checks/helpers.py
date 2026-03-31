from urllib.parse import urlparse

import requests

from apps.common.utils.targets import build_candidate_urls_for_target, parse_target_parts


SECURITY_HEADER_RECOMMENDATIONS = {
    "strict-transport-security": "Enable HSTS with a long max-age on HTTPS responses.",
    "content-security-policy": "Add a restrictive Content-Security-Policy header.",
    "x-frame-options": "Set X-Frame-Options to DENY or SAMEORIGIN.",
    "x-content-type-options": "Set X-Content-Type-Options to nosniff.",
    "referrer-policy": "Set a strict Referrer-Policy.",
}



def normalize_domain(domain: str):
    domain = (domain or "").strip()
    if not domain:
        return []
    return build_candidate_urls_for_target(domain)



def host_from_value(value: str) -> str:
    return parse_target_parts(value)["host"]



def port_from_value(value: str, default_port=443) -> int:
    return parse_target_parts(value).get("port") or default_port



def build_finding(category, severity, title, description, endpoint="", file_path="", recommendation="", evidence=None):
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "description": description,
        "endpoint": endpoint,
        "file_path": file_path,
        "recommendation": recommendation,
        "evidence": evidence or {},
    }



def safe_request(method, url, **kwargs):
    timeout = kwargs.pop("timeout", 8)
    allow_insecure_fallback = kwargs.pop("allow_insecure_fallback", False)
    try:
        response = requests.request(method=method, url=url, timeout=timeout, **kwargs)
        return response, None
    except requests.exceptions.SSLError as exc:
        if allow_insecure_fallback:
            try:
                response = requests.request(method=method, url=url, timeout=timeout, verify=False, **kwargs)
                return response, f"SSL verification failed; retried insecurely for header inspection: {exc}"
            except Exception as retry_exc:
                return None, str(retry_exc)
        return None, str(exc)
    except Exception as exc:
        return None, str(exc)



def severity_weight(severity):
    return {
        "critical": 18,
        "warning": 8,
        "info": 2,
    }.get(severity, 0)
