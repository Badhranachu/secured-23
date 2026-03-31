import hashlib
import re
from urllib.parse import urljoin

import requests
from django.conf import settings

from apps.surface_scan.services.result_utils import clean_text, status_payload

TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
HTML_LANG_PATTERN = re.compile(r"<html[^>]*\blang=[\"']?([^\"'>\s]+)", re.IGNORECASE)
META_GENERATOR_PATTERN = re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", re.IGNORECASE)



def _safe_headers():
    return {"User-Agent": getattr(settings, "SURFACE_SCAN_USER_AGENT", "AEGIS AI Surface Scanner/1.0")}



def _looks_like_html(body, content_type):
    lowered = (body or "").lower()
    return "<html" in lowered or "text/html" in (content_type or "").lower()



def _fetch_public_url(url, binary=False):
    try:
        response = requests.get(
            url,
            timeout=(getattr(settings, "SURFACE_SCAN_CONNECT_TIMEOUT", 4), getattr(settings, "SURFACE_SCAN_READ_TIMEOUT", 6)),
            headers=_safe_headers(),
            allow_redirects=True,
        )
        body_bytes = response.content[:12000] if binary else response.content
        body_text = response.text[:12000] if not binary and ("text" in response.headers.get("content-type", "").lower() or "json" in response.headers.get("content-type", "").lower()) else ""
        content_type = clean_text(response.headers.get("content-type"))
        content_length = response.headers.get("content-length")
        return {
            "status": "success",
            "url": url,
            "status_code": response.status_code,
            "final_url": clean_text(response.url),
            "content_type": content_type,
            "content_length": int(content_length) if str(content_length).isdigit() else len(response.content or b""),
            "headers": {key.lower(): clean_text(value) for key, value in response.headers.items()},
            "body": body_text,
            "body_bytes": body_bytes,
            "reachable": True,
            "error_message": "",
        }
    except Exception as exc:
        return {
            "status": "check_failed",
            "url": url,
            "status_code": None,
            "final_url": "",
            "content_type": "",
            "content_length": None,
            "headers": {},
            "body": "",
            "body_bytes": b"",
            "reachable": False,
            "error_message": clean_text(exc),
        }



def _file_result(path, fetched, validator_name):
    if fetched.get("status") == "check_failed":
        return {
            "path": path,
            "status": "check_failed",
            "final_url": fetched.get("final_url", ""),
            "status_code": fetched.get("status_code"),
            "content_type": fetched.get("content_type", ""),
            "content_length": fetched.get("content_length"),
            "is_valid_expected_file": False,
            "validation_notes": [fetched.get("error_message") or "File check failed."],
        }

    if (fetched.get("status_code") or 0) >= 400:
        return {
            "path": path,
            "status": "not_found",
            "final_url": fetched.get("final_url", ""),
            "status_code": fetched.get("status_code"),
            "content_type": fetched.get("content_type", ""),
            "content_length": fetched.get("content_length"),
            "is_valid_expected_file": False,
            "validation_notes": [f"{path} returned HTTP {fetched.get('status_code')}"],
        }

    body = fetched.get("body", "")
    content_type = fetched.get("content_type", "")
    notes = []
    is_valid = True

    if validator_name == "robots":
        markers = ["user-agent:", "disallow:", "allow:"]
        present_markers = [marker for marker in markers if marker in body.lower()]
        if _looks_like_html(body, content_type):
            is_valid = False
            notes.append("Response looks like generic HTML instead of a real robots.txt file.")
        if not present_markers:
            is_valid = False
            notes.append("robots.txt markers like User-agent or Disallow were not detected.")
        else:
            notes.append(f"Detected robots markers: {', '.join(present_markers)}")
    elif validator_name == "security":
        markers = ["contact:", "expires:", "policy:"]
        present_markers = [marker for marker in markers if marker in body.lower()]
        if _looks_like_html(body, content_type):
            is_valid = False
            notes.append("Response looks like generic HTML instead of security.txt content.")
        if "contact:" not in body.lower():
            is_valid = False
            notes.append("security.txt is missing Contact:.")
        if not present_markers:
            is_valid = False
            notes.append("Expected security.txt markers were not detected.")
        else:
            notes.append(f"Detected security.txt markers: {', '.join(present_markers)}")
    elif validator_name == "favicon":
        if not fetched.get("content_length"):
            is_valid = False
            notes.append("favicon.ico returned no content.")
        else:
            notes.append("favicon.ico returned binary content.")

    return {
        "path": path,
        "status": "success" if is_valid else "partial",
        "final_url": fetched.get("final_url", ""),
        "status_code": fetched.get("status_code"),
        "content_type": content_type,
        "content_length": fetched.get("content_length"),
        "is_valid_expected_file": is_valid,
        "validation_notes": notes,
    }



def inspect_public_files(hostname: str, http_snapshot):
    base_url = http_snapshot.get("base_url") or (f"https://{hostname}" if http_snapshot.get("https", {}).get("reachable") else f"http://{hostname}")
    homepage_headers = http_snapshot.get("selected_headers", {}) or {}
    homepage_body = http_snapshot.get("selected_html", "") or ""
    title_match = TITLE_PATTERN.search(homepage_body)
    lang_match = HTML_LANG_PATTERN.search(homepage_body)
    generator_match = META_GENERATOR_PATTERN.search(homepage_body)

    favicon_item = _fetch_public_url(urljoin(base_url.rstrip("/") + "/", "favicon.ico"), binary=True)
    robots_item = _fetch_public_url(urljoin(base_url.rstrip("/") + "/", "robots.txt"))
    security_item = _fetch_public_url(urljoin(base_url.rstrip("/") + "/", ".well-known/security.txt"))

    files = {
        "/robots.txt": _file_result("/robots.txt", robots_item, "robots"),
        "/.well-known/security.txt": _file_result("/.well-known/security.txt", security_item, "security"),
        "/favicon.ico": {
            **_file_result("/favicon.ico", favicon_item, "favicon"),
            "favicon_hash": hashlib.sha256(favicon_item.get("body_bytes", b"")).hexdigest() if favicon_item.get("body_bytes") else None,
        },
    }

    framework_hints = []
    body_lower = homepage_body.lower()
    for marker, label in [
        ("__next", "Next.js"),
        ("react", "React"),
        ("ng-version", "Angular"),
        ("vue", "Vue"),
        ("wp-content", "WordPress"),
    ]:
        if marker in body_lower and label not in framework_hints:
            framework_hints.append(label)

    homepage = {
        "status": "success" if http_snapshot.get("final_url") else "not_available",
        "title": clean_text(title_match.group(1)) if title_match else None,
        "html_lang": clean_text(lang_match.group(1)) if lang_match else None,
        "meta_generator": clean_text(generator_match.group(1)) if generator_match else None,
        "response_content_length": http_snapshot.get("selected_content_length"),
        "cache_headers": {
            "cache_control": clean_text(homepage_headers.get("cache-control")),
            "etag": clean_text(homepage_headers.get("etag")),
            "vary": clean_text(homepage_headers.get("vary")),
        },
        "server_header": clean_text(homepage_headers.get("server")),
        "server": clean_text(homepage_headers.get("server")),
        "x_powered_by": clean_text(homepage_headers.get("x-powered-by")),
        "powered_by": clean_text(homepage_headers.get("x-powered-by")),
        "framework_hints": framework_hints,
        "favicon_hash": files["/favicon.ico"].get("favicon_hash"),
        "homepage_fetch_status": http_snapshot.get("status", "not_available"),
        "spa_shell_detected": "<div id=\"root\"" in body_lower or "<div id='root'" in body_lower or "<app-root" in body_lower,
        "final_url": http_snapshot.get("final_url", ""),
        "content_type": http_snapshot.get("selected_content_type", ""),
    }

    overall_status = "success"
    if any(item.get("status") == "check_failed" for item in files.values()):
        overall_status = "partial"
    elif any(item.get("status") in {"partial", "not_found"} for item in files.values()):
        overall_status = "partial"

    return status_payload(
        overall_status,
        base_url=base_url,
        files=files,
        homepage=homepage,
    )

