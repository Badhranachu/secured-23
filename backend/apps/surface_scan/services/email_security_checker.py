import re

from apps.surface_scan.services.result_utils import clean_text, status_payload

DMARC_POLICY_PATTERN = re.compile(r"\bp=([a-z]+)", re.IGNORECASE)



def analyze_email_security(dns_snapshot):
    records = dns_snapshot.get("records", {}) if isinstance(dns_snapshot, dict) else {}
    analysis = dns_snapshot.get("analysis", {}) if isinstance(dns_snapshot, dict) else {}

    mx_values = records.get("mx", {}).get("values", [])
    spf_value = analysis.get("spf_value")
    dmarc_value = analysis.get("dmarc_value")
    mx_present = bool(mx_values)
    spf_present = bool(spf_value)
    dmarc_present = bool(dmarc_value)
    mail_enabled = bool(analysis.get("mail_enabled") or mx_present or spf_present or dmarc_present)

    dmarc_policy = None
    if dmarc_value:
        match = DMARC_POLICY_PATTERN.search(dmarc_value)
        dmarc_policy = clean_text(match.group(1)).lower() if match else None

    if mx_present and not spf_present and not dmarc_present:
        spoofing_risk = "high"
    elif mx_present and spf_present and not dmarc_present:
        spoofing_risk = "medium"
    elif mx_present and dmarc_policy == "none":
        spoofing_risk = "medium"
    elif mx_present and spf_present and dmarc_policy in {"reject", "quarantine"}:
        spoofing_risk = "low"
    elif not mx_present and not spf_present and not dmarc_present:
        spoofing_risk = "unknown_or_unconfigured"
    else:
        spoofing_risk = "medium"

    status = "success"
    if dns_snapshot.get("status") == "check_failed":
        status = "check_failed"
    elif dns_snapshot.get("status") == "partial":
        status = "partial"

    return status_payload(
        status,
        mail_enabled=mail_enabled,
        mx_present=mx_present,
        spf_present=spf_present,
        spf_value=spf_value,
        dmarc_present=dmarc_present,
        dmarc_value=dmarc_value,
        dmarc_policy=dmarc_policy,
        dkim_test_status="not_tested_without_selector",
        email_spoofing_risk=spoofing_risk,
        provider_clues=analysis.get("provider_clues", []),
    )
