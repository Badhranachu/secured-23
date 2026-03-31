try:
    import dns.exception
    import dns.resolver
except Exception:  # pragma: no cover - optional local dependency
    dns = None

from apps.common.utils.targets import dns_lookup_name_for_target
from apps.surface_scan.services.result_utils import clean_list, clean_text, pick_status, status_payload
from apps.surface_scan.services.timing_utils import elapsed_ms, timer_start

DNS_TIMEOUT = 4
PROVIDER_HINTS = {
    "cloudflare": "Cloudflare",
    "awsdns": "AWS Route 53",
    "googledomains": "Google Domains",
    "google": "Google Workspace",
    "domaincontrol": "GoDaddy",
    "azure-dns": "Azure DNS",
    "outlook": "Microsoft 365",
    "protection.outlook": "Microsoft 365",
    "secureserver": "GoDaddy",
    "yahoodns": "Yahoo",
    "zoho": "Zoho Mail",
    "sendgrid": "SendGrid",
    "mailgun": "Mailgun",
    "github.io": "GitHub Pages",
    "vercel-dns": "Vercel",
    "netlify": "Netlify",
}

RECORD_MAP = {
    "a": ("A", None),
    "aaaa": ("AAAA", None),
    "cname": ("CNAME", None),
    "mx": ("MX", None),
    "ns": ("NS", None),
    "txt": ("TXT", None),
    "dmarc": ("TXT", "_dmarc.{hostname}"),
}



def _resolver():
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    return resolver



def _extract_values(answers, record_key):
    values = []
    raw_values = []
    ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
    for answer in answers:
        if record_key == "mx":
            exchange = clean_text(str(getattr(answer, "exchange", "")).rstrip("."))
            raw_values.append({"priority": getattr(answer, "preference", None), "exchange": exchange})
            values.append({"priority": getattr(answer, "preference", None), "exchange": exchange})
        elif record_key in {"txt", "dmarc"}:
            if hasattr(answer, "strings"):
                text = "".join(part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part) for part in answer.strings)
            else:
                text = answer.to_text().strip('"')
            cleaned = clean_text(text)
            raw_values.append(cleaned)
            values.append(cleaned)
        else:
            cleaned = clean_text(str(answer).rstrip("."))
            raw_values.append(cleaned)
            values.append(cleaned)
    values = clean_list(values) if record_key not in {"mx"} else values
    raw_values = clean_list(raw_values) if record_key not in {"mx"} else raw_values
    return values, raw_values, ttl



def _query_record(lookup_name, record_key):
    if dns is None:
        return status_payload(
            "not_available",
            record_type=RECORD_MAP[record_key][0],
            values=[],
            raw_values=[],
            ttl=None,
            error_message="dnspython is not installed.",
        )

    record_type, template = RECORD_MAP[record_key]
    query_name = template.format(hostname=lookup_name) if template else lookup_name
    started = timer_start()
    try:
        answers = _resolver().resolve(query_name, record_type)
        values, raw_values, ttl = _extract_values(answers, record_key)
        return status_payload(
            "success" if values else "not_found",
            record_type=record_type,
            query_name=query_name,
            values=values,
            raw_values=raw_values,
            ttl=ttl,
            lookup_time_ms=elapsed_ms(started),
            error_message="",
        )
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return status_payload(
            "not_found",
            record_type=record_type,
            query_name=query_name,
            values=[],
            raw_values=[],
            ttl=None,
            lookup_time_ms=elapsed_ms(started),
            error_message="",
        )
    except Exception as exc:
        return status_payload(
            "check_failed",
            record_type=record_type,
            query_name=query_name,
            values=[],
            raw_values=[],
            ttl=None,
            lookup_time_ms=elapsed_ms(started),
            error_message=clean_text(exc),
        )



def _extract_provider_clues(*sources):
    clues = []
    for source in sources:
        for item in source or []:
            haystack = clean_text(item).lower()
            for marker, provider in PROVIDER_HINTS.items():
                if marker in haystack and provider not in clues:
                    clues.append(provider)
    return clues


def _zone_lookup_name(hostname):
    cleaned = clean_text(hostname).lower().strip('.')
    if cleaned.startswith('www.') and cleaned.count('.') >= 2:
        return cleaned[4:]
    return cleaned



def collect_dns_snapshot(target: str):
    host_lookup_name = dns_lookup_name_for_target(target)
    if not host_lookup_name:
        return status_payload(
            "not_available",
            hostname=target,
            zone_hostname=target,
            resolver="not_applicable",
            total_lookup_time_ms=0,
            records={
                key: status_payload("not_available", record_type=record_type, values=[], raw_values=[], ttl=None, error_message="DNS lookups do not apply to raw IP or localhost targets.")
                for key, (record_type, _) in RECORD_MAP.items()
            },
            analysis={
                "spf_present": False,
                "spf_value": None,
                "dmarc_present": False,
                "dmarc_value": None,
                "provider_clues": [],
                "mail_enabled": False,
                "mx_present": False,
                "dkim_status": "not_applicable_for_ip_target",
            },
            summary={"found_records_count": 0, "not_found_count": 0, "failed_count": 0},
            errors={},
        )

    zone_lookup_name = _zone_lookup_name(host_lookup_name)
    started = timer_start()
    records = {
        "a": _query_record(host_lookup_name, "a"),
        "aaaa": _query_record(host_lookup_name, "aaaa"),
        "cname": _query_record(host_lookup_name, "cname"),
        "mx": _query_record(zone_lookup_name, "mx"),
        "ns": _query_record(zone_lookup_name, "ns"),
        "txt": _query_record(zone_lookup_name, "txt"),
        "dmarc": _query_record(zone_lookup_name, "dmarc"),
    }
    record_statuses = [item.get("status") for item in records.values()]

    ns_values = records["ns"].get("values", [])
    mx_values = [item.get("exchange", "") for item in records["mx"].get("values", [])]
    txt_values = records["txt"].get("values", [])
    dmarc_values = records["dmarc"].get("values", [])

    provider_clues = _extract_provider_clues(ns_values, mx_values, txt_values, dmarc_values)
    spf_value = next((item for item in txt_values if item.lower().startswith("v=spf1")), None)
    dmarc_value = next((item for item in dmarc_values if "v=dmarc1" in item.lower()), None)
    mail_enabled = bool(records["mx"].get("values") or spf_value or dmarc_value)

    errors = {
        key: value.get("error_message", "")
        for key, value in records.items()
        if value.get("status") == "check_failed" and value.get("error_message")
    }

    return status_payload(
        pick_status(record_statuses),
        hostname=host_lookup_name,
        zone_hostname=zone_lookup_name,
        resolver="dnspython" if dns is not None else "unavailable",
        total_lookup_time_ms=elapsed_ms(started),
        records=records,
        analysis={
            "spf_present": bool(spf_value),
            "spf_value": spf_value,
            "dmarc_present": bool(dmarc_value),
            "dmarc_value": dmarc_value,
            "provider_clues": provider_clues,
            "mail_enabled": mail_enabled,
            "mx_present": bool(records["mx"].get("values")),
            "dkim_status": "not_tested_without_selector",
            "record_scope": {
                "host_lookup_name": host_lookup_name,
                "zone_lookup_name": zone_lookup_name,
            },
        },
        summary={
            "found_records_count": sum(1 for item in records.values() if item.get("status") == "success"),
            "not_found_count": sum(1 for item in records.values() if item.get("status") == "not_found"),
            "failed_count": sum(1 for item in records.values() if item.get("status") == "check_failed"),
        },
        errors=errors,
    )
