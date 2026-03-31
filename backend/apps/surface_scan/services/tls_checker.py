import socket
import ssl
from datetime import datetime, timezone

import requests
from django.conf import settings

from apps.common.utils.targets import parse_target_parts
from apps.surface_scan.services.result_utils import clean_list, clean_text, status_payload
from apps.surface_scan.services.timing_utils import elapsed_ms, timer_start

DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"



def _flatten_name(parts):
    rows = []
    for part in parts or []:
        for key, value in part:
            rows.append(f"{clean_text(key)}={clean_text(value)}")
    return ", ".join(rows)



def _common_name(parts):
    for part in parts or []:
        for key, value in part:
            if str(key).lower() == "commonname":
                return clean_text(value)
    return ""



def _parse_datetime(raw_value):
    if not raw_value:
        return None
    try:
        return datetime.strptime(raw_value, DATE_FORMAT).replace(tzinfo=timezone.utc)
    except Exception:
        return None



def _ssl_grade(hostname, timeout):
    if not getattr(settings, "SSL_LABS_ENABLED", False):
        return "not_available", "not_available", "SSL Labs lookup is disabled."

    try:
        response = requests.get(
            getattr(settings, "SSL_LABS_API_URL", "https://api.ssllabs.com/api/v3/analyze"),
            params={"host": hostname, "publish": "off", "all": "done", "fromCache": "on"},
            timeout=(timeout, timeout + 2),
            headers={"User-Agent": getattr(settings, "SURFACE_SCAN_USER_AGENT", "AEGIS AI Surface Scanner/1.0")},
        )
        if not response.ok:
            return "not_available", "check_failed", f"SSL Labs returned HTTP {response.status_code}."
        payload = response.json() if response.content else {}
        endpoints = payload.get("endpoints") or []
        grades = [clean_text(item.get("grade")) for item in endpoints if item.get("grade")]
        if grades:
            return grades[0], "found", ""
        return "not_available", "not_available", "SSL Labs did not return a grade for this host."
    except Exception as exc:
        return "not_available", "check_failed", clean_text(exc)



def inspect_tls(target: str):
    parts = parse_target_parts(target)
    hostname = parts["host"]
    port = parts["port"] or 443
    timeout = getattr(settings, "SURFACE_SCAN_CONNECT_TIMEOUT", 4)
    started = timer_start()
    ssl_grade, ssl_grade_status, ssl_grade_error = _ssl_grade(hostname, timeout)
    result = {
        "status": "check_failed",
        "reachable": False,
        "subject": None,
        "issued_to": None,
        "issuer": None,
        "issuer_name": None,
        "valid_from": None,
        "valid_from_iso": None,
        "certificate_expiry": None,
        "certificate_expiry_iso": None,
        "days_to_expiry": None,
        "hostname_match": None,
        "san_count": 0,
        "san_names": [],
        "wildcard_certificate": None,
        "tls_version": None,
        "cipher": None,
        "chain_validation_status": "not_available",
        "ocsp_stapling_status": "not_available",
        "ssl_grade": ssl_grade,
        "ssl_grade_status": ssl_grade_status,
        "ssl_grade_error": ssl_grade_error,
        "lookup_time_ms": None,
        "port": port,
        "error_message": "",
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                cipher = secure_sock.cipher()
                result["lookup_time_ms"] = elapsed_ms(started)
                result["tls_version"] = clean_text(secure_sock.version()) or None
                result["cipher"] = clean_text(cipher[0]) if cipher else None
                result["reachable"] = True

        subject_cn = _common_name(cert.get("subject"))
        issuer_cn = _common_name(cert.get("issuer"))
        san_names = clean_list([value for key, value in cert.get("subjectAltName", []) if key == "DNS"])
        valid_from = _parse_datetime(cert.get("notBefore"))
        expires_at = _parse_datetime(cert.get("notAfter"))

        hostname_match = False
        try:
            ssl.match_hostname(cert, hostname)
            hostname_match = True
        except Exception:
            hostname_match = False

        result.update(
            {
                "status": "success",
                "subject": _flatten_name(cert.get("subject")) or None,
                "issued_to": subject_cn or None,
                "issuer": _flatten_name(cert.get("issuer")) or None,
                "issuer_name": issuer_cn or _flatten_name(cert.get("issuer")) or None,
                "valid_from": valid_from.isoformat() if valid_from else None,
                "valid_from_iso": valid_from.isoformat() if valid_from else None,
                "certificate_expiry": expires_at.isoformat() if expires_at else None,
                "certificate_expiry_iso": expires_at.isoformat() if expires_at else None,
                "days_to_expiry": (expires_at - datetime.now(timezone.utc)).days if expires_at else None,
                "hostname_match": hostname_match,
                "san_count": len(san_names),
                "san_names": san_names,
                "wildcard_certificate": any(item.startswith("*.") for item in san_names) or (subject_cn.startswith("*.") if subject_cn else False),
                "chain_validation_status": "validated_by_default_context",
                "ocsp_stapling_status": "not_available",
            }
        )
    except Exception as exc:
        result.update(
            {
                "status": "check_failed",
                "error_message": clean_text(exc),
                "lookup_time_ms": elapsed_ms(started),
            }
        )

    return status_payload(result.pop("status"), **result)
