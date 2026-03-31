import requests
from django.conf import settings

from apps.common.utils.targets import dns_lookup_name_for_target
from apps.surface_scan.services.result_utils import clean_list, clean_text, status_payload



def discover_ct_subdomains(target: str):
    lookup_name = dns_lookup_name_for_target(target)
    if not lookup_name:
        return status_payload(
            "not_available",
            ct_source="not_applicable",
            ct_lookup_status="not_available",
            lookup_succeeded=False,
            raw_host_count=0,
            deduped_host_count=0,
            hostnames=[],
            discovered=[],
            note="Certificate transparency lookups do not apply to raw IP or localhost targets.",
        )

    if not getattr(settings, "SURFACE_SCAN_CT_ENABLED", True):
        return status_payload(
            "not_available",
            ct_source="disabled",
            ct_lookup_status="not_available",
            lookup_succeeded=False,
            raw_host_count=0,
            deduped_host_count=0,
            hostnames=[],
            discovered=[],
            note="Certificate transparency lookups are disabled.",
        )

    try:
        response = requests.get(
            getattr(settings, "CRTSH_BASE_URL", "https://crt.sh/"),
            params={"q": f"%.{lookup_name}", "output": "json"},
            timeout=(getattr(settings, "SURFACE_SCAN_CONNECT_TIMEOUT", 4), getattr(settings, "SURFACE_SCAN_READ_TIMEOUT", 6)),
            headers={"User-Agent": getattr(settings, "SURFACE_SCAN_USER_AGENT", "AEGIS AI Surface Scanner/1.0")},
        )
        if not response.ok:
            return status_payload(
                "check_failed",
                ct_source="crt.sh",
                ct_lookup_status="check_failed",
                lookup_succeeded=False,
                raw_host_count=0,
                deduped_host_count=0,
                hostnames=[],
                discovered=[],
                note=f"crt.sh returned HTTP {response.status_code}.",
            )
        payload = response.json() if response.content else []
    except Exception as exc:
        return status_payload(
            "check_failed",
            ct_source="crt.sh",
            ct_lookup_status="check_failed",
            lookup_succeeded=False,
            raw_host_count=0,
            deduped_host_count=0,
            hostnames=[],
            discovered=[],
            note=f"Certificate transparency lookup failed: {clean_text(exc)}",
        )

    raw_hosts = []
    deduped_hosts = []
    seen = set()
    for row in payload:
        raw_value = clean_text(row.get("name_value", ""))
        for candidate in raw_value.splitlines():
            entry = clean_text(candidate).lower().lstrip("*.")
            if not entry or not (entry == lookup_name or entry.endswith(f".{lookup_name}")):
                continue
            raw_hosts.append(entry)
            if entry in seen:
                continue
            seen.add(entry)
            deduped_hosts.append(entry)

    deduped_hosts = clean_list(sorted(deduped_hosts))
    lookup_status = "success_zero_results" if not deduped_hosts else "success"
    if not raw_hosts and not deduped_hosts:
        lookup_status = "no_matches_found"

    discovered = [
        {
            "hostname": item,
            "source": "crt.sh public cert history",
            "status": "public cert history only; may not be live",
        }
        for item in deduped_hosts[:100]
    ]

    return status_payload(
        "success",
        ct_source="crt.sh",
        ct_lookup_status=lookup_status,
        lookup_succeeded=True,
        raw_host_count=len(raw_hosts),
        deduped_host_count=len(deduped_hosts),
        hostnames=deduped_hosts[:100],
        discovered=discovered,
        note="Results come from public certificate history and may include stale or inactive hosts.",
    )
