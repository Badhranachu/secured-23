import re
from urllib.parse import urlparse

STANDARD_STATUSES = {"success", "partial", "not_found", "not_available", "check_failed"}
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


def clean_text(value, default=""):
    if value is None:
        return default
    text = str(value).replace("\ufffd", "").replace("\uFFFD", "")
    text = _CONTROL_CHARS.sub(" ", text)
    text = text.strip()
    return text if text else default


def clean_list(values):
    cleaned = []
    seen = set()
    for value in values or []:
        item = clean_text(value)
        if not item or item in seen:
            continue
        seen.add(item)
        cleaned.append(item)
    return cleaned


def status_payload(status, **extra):
    normalized_status = status if status in STANDARD_STATUSES else "check_failed"
    payload = {"status": normalized_status}
    payload.update(extra)
    return payload


def pick_status(statuses):
    values = [item for item in statuses if item]
    if not values:
        return "not_available"
    if all(item == "success" for item in values):
        return "success"
    if any(item == "check_failed" for item in values):
        return "partial" if any(item == "success" for item in values) else "check_failed"
    if any(item == "partial" for item in values):
        return "partial"
    if any(item == "success" for item in values):
        return "partial"
    if all(item == "not_found" for item in values):
        return "not_found"
    if all(item == "not_available" for item in values):
        return "not_available"
    return "partial"


def hostname_from_url(url):
    if not url:
        return ""
    try:
        return clean_text(urlparse(url).hostname or "")
    except Exception:
        return ""


def int_or_none(value):
    try:
        return int(value)
    except Exception:
        return None


def bool_label(value):
    return "yes" if bool(value) else "no"
