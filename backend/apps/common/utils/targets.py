import ipaddress
import re
from urllib.parse import urlparse

HOSTNAME_PATTERN = re.compile(r"^[a-z0-9.-]+$")


class TargetValidationError(ValueError):
    pass



def _validate_hostname(hostname: str) -> str:
    hostname = (hostname or "").strip().lower().strip(".")
    if not hostname:
        raise TargetValidationError("A target host is required.")
    if hostname == "localhost":
        return hostname

    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        pass

    try:
        hostname = hostname.encode("idna").decode("ascii")
    except Exception as exc:
        raise TargetValidationError("The target host could not be normalized safely.") from exc

    if "." not in hostname:
        raise TargetValidationError("Enter a valid domain, IP address, localhost, or host with port.")
    if len(hostname) > 253 or not HOSTNAME_PATTERN.match(hostname):
        raise TargetValidationError("Target host contains invalid characters.")

    labels = hostname.split(".")
    for label in labels:
        if not label or len(label) > 63:
            raise TargetValidationError("Host labels must be between 1 and 63 characters.")
        if label.startswith("-") or label.endswith("-"):
            raise TargetValidationError("Host labels cannot start or end with a hyphen.")

    return hostname



def parse_target_parts(raw_value: str):
    value = (raw_value or "").strip()
    if not value:
        raise TargetValidationError("A domain or IP target is required.")

    has_scheme = "://" in value
    parsed = urlparse(value if has_scheme else f"//{value}", scheme="https")

    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("Enter a valid TCP port between 1 and 65535.") from exc

    if parsed.path and parsed.path not in {"", "/"}:
        raise TargetValidationError("Enter only the host or host:port in the target field, not a path.")
    if parsed.params or parsed.query or parsed.fragment:
        raise TargetValidationError("Enter only the host or host:port in the target field.")

    scheme = parsed.scheme.lower() if has_scheme else ""
    if has_scheme and scheme not in {"http", "https"}:
        raise TargetValidationError("Only http:// and https:// targets are supported.")

    host = _validate_hostname(parsed.hostname or parsed.netloc or parsed.path)
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    hostport = f"{host}:{port}" if port else host
    normalized = f"{scheme}://{hostport}" if has_scheme else hostport

    return {
        "raw": value,
        "normalized": normalized,
        "host": host,
        "port": port,
        "scheme": scheme or None,
        "has_scheme": has_scheme,
        "hostport": hostport,
        "is_ip": is_ip,
        "is_hostname": not is_ip,
    }



def normalize_target_value(raw_value: str) -> str:
    return parse_target_parts(raw_value)["normalized"]



def target_display_name(raw_value: str) -> str:
    return parse_target_parts(raw_value)["hostport"]



def default_api_base_url_for_target(raw_value: str) -> str:
    parts = parse_target_parts(raw_value)
    if parts["scheme"]:
        return f"{parts['scheme']}://{parts['hostport']}"
    if parts["port"]:
        return f"http://{parts['hostport']}"
    return f"https://{parts['hostport']}"



def build_candidate_urls_for_target(raw_value: str):
    parts = parse_target_parts(raw_value)
    hostport = parts["hostport"]
    if parts["scheme"] == "http":
        return [f"http://{hostport}", f"https://{hostport}"]
    if parts["scheme"] == "https":
        return [f"https://{hostport}", f"http://{hostport}"]
    if parts["port"]:
        return [f"http://{hostport}", f"https://{hostport}"]
    return [f"https://{hostport}", f"http://{hostport}"]



def dns_lookup_name_for_target(raw_value: str):
    parts = parse_target_parts(raw_value)
    if parts["is_ip"] or parts["host"] == "localhost":
        return None
    return parts["host"]
