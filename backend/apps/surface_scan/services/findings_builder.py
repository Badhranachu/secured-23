from apps.surface_scan.services.result_utils import clean_text


HEADER_DEDUCTION_KEYS = {
    "strict-transport-security": ("hsts_missing", 10),
    "content-security-policy": ("csp_missing", 10),
    "x-frame-options": ("xfo_missing", 5),
    "x-content-type-options": ("xcto_missing", 5),
    "referrer-policy": ("referrer_missing", 5),
}



def _finding(
    *,
    category,
    severity,
    key,
    title,
    description,
    observed_value,
    expected_value,
    evidence_source,
    module_name,
    recommendation,
    confidence="high",
    deduction_key=None,
    deduction_points=0,
):
    return {
        "category": category,
        "severity": severity,
        "key": key,
        "title": title,
        "description": description,
        "value": observed_value,
        "observed_value": observed_value,
        "expected_value": expected_value,
        "evidence_source": evidence_source,
        "module_name": module_name,
        "recommendation": recommendation,
        "confidence": confidence,
        "deduction_key": deduction_key,
        "deduction_points": deduction_points,
        "evidence": {
            "observed_value": observed_value,
            "expected_value": expected_value,
            "evidence_source": evidence_source,
            "module_name": module_name,
            "confidence": confidence,
        },
    }



def build_surface_findings(hostname, dns_snapshot, http_snapshot, header_snapshot, tls_snapshot, ct_snapshot, public_files_snapshot, fingerprint_snapshot, email_security_snapshot):
    findings = []
    http_result = http_snapshot.get("http", {})
    https_result = http_snapshot.get("https", {})
    redirects = http_snapshot.get("redirect_analysis", {})
    public_files = public_files_snapshot.get("files", {})
    security_txt = public_files.get("/.well-known/security.txt", {})
    robots_txt = public_files.get("/robots.txt", {})

    if not https_result.get("reachable"):
        findings.append(
            _finding(
                category="reachability",
                severity="critical",
                key="https_missing",
                title="HTTPS Missing",
                description="The domain did not respond successfully over HTTPS during this safe public scan.",
                observed_value=clean_text(https_result.get("error_message") or "HTTPS request failed"),
                expected_value="A public HTTPS response with a valid certificate",
                evidence_source="https reachability check",
                module_name="http_checker",
                recommendation="Enable HTTPS and ensure a valid certificate is deployed for the public hostname.",
                confidence="high",
                deduction_key="https_missing",
                deduction_points=25,
            )
        )

    if redirects.get("redirect_mismatch_warning") or (http_result.get("reachable") and not redirects.get("https_enforced")):
        findings.append(
            _finding(
                category="redirects",
                severity="warning",
                key="insecure_redirect_behavior",
                title="Redirect Behavior Needs Review",
                description="The redirect path was unusual, downgraded traffic, or did not cleanly enforce HTTPS.",
                observed_value=clean_text(redirects.get("final_url") or "Redirect chain did not enforce HTTPS cleanly"),
                expected_value="HTTP should redirect directly to the canonical HTTPS URL",
                evidence_source="redirect chain analysis",
                module_name="http_checker",
                recommendation="Review redirect rules and ensure traffic lands on the intended HTTPS canonical host in as few steps as possible.",
                confidence="high",
                deduction_key="insecure_redirect_behavior",
                deduction_points=10,
            )
        )

    if https_result.get("reachable") and tls_snapshot.get("status") == "check_failed":
        findings.append(
            _finding(
                category="tls",
                severity="warning",
                key="tls_metadata_missing",
                title="TLS Metadata Incomplete",
                description="HTTPS responded, but certificate details could not be collected cleanly.",
                observed_value=clean_text(tls_snapshot.get("error_message") or "TLS inspection failed"),
                expected_value="Certificate details should be retrievable for the public hostname",
                evidence_source="tls certificate inspection",
                module_name="tls_checker",
                recommendation="Verify the certificate chain and hostname bindings on the public site.",
                confidence="medium",
            )
        )

    if tls_snapshot.get("hostname_match") is False:
        findings.append(
            _finding(
                category="tls",
                severity="critical",
                key="certificate_invalid",
                title="Certificate Hostname Mismatch",
                description="The certificate presented for HTTPS does not appear to match the requested hostname.",
                observed_value=clean_text(tls_snapshot.get("issued_to") or "hostname mismatch"),
                expected_value=f"Certificate valid for {hostname}",
                evidence_source="tls certificate inspection",
                module_name="tls_checker",
                recommendation="Deploy a certificate whose SAN or common name matches the scanned hostname.",
                confidence="high",
                deduction_key="certificate_invalid",
                deduction_points=25,
            )
        )

    if tls_snapshot.get("days_to_expiry") is not None:
        if tls_snapshot["days_to_expiry"] < 0:
            findings.append(
                _finding(
                    category="tls",
                    severity="critical",
                    key="cert_expired",
                    title="Certificate Expired",
                    description="The TLS certificate is expired.",
                    observed_value=clean_text(tls_snapshot.get("certificate_expiry") or "expired certificate"),
                    expected_value="An unexpired certificate with healthy renewal margin",
                    evidence_source="tls certificate inspection",
                    module_name="tls_checker",
                    recommendation="Renew and redeploy the TLS certificate immediately.",
                    confidence="high",
                    deduction_key="cert_expired",
                    deduction_points=25,
                )
            )
        elif tls_snapshot["days_to_expiry"] <= 15:
            findings.append(
                _finding(
                    category="tls",
                    severity="warning",
                    key="cert_expiring_soon",
                    title="Certificate Expiring Soon",
                    description="The TLS certificate expires within 15 days.",
                    observed_value=f"{tls_snapshot['days_to_expiry']} days remaining",
                    expected_value="More than 15 days of certificate validity remaining",
                    evidence_source="tls certificate inspection",
                    module_name="tls_checker",
                    recommendation="Renew the certificate soon to avoid trust warnings or downtime.",
                    confidence="high",
                    deduction_key="cert_expiring_soon",
                    deduction_points=15,
                )
            )

    for evaluation in header_snapshot.get("evaluations", []):
        deduction = HEADER_DEDUCTION_KEYS.get(evaluation["name"])
        if evaluation.get("classification") == "missing":
            severity = "warning" if evaluation["name"] in {"strict-transport-security", "content-security-policy"} else "info"
            findings.append(
                _finding(
                    category="headers",
                    severity=severity,
                    key=(deduction[0] if deduction else f"{evaluation['name']}_missing"),
                    title=f"{evaluation['name'].replace('-', ' ').title()} Missing",
                    description=evaluation.get("message") or "Required security header is missing.",
                    observed_value=evaluation.get("observed_value") or "header absent",
                    expected_value=evaluation.get("expected_value") or "Header should be present with a secure value",
                    evidence_source=evaluation.get("evidence_source") or "response headers",
                    module_name="header_checker",
                    recommendation=evaluation.get("recommendation") or "Add the missing security header.",
                    confidence="high",
                    deduction_key=deduction[0] if deduction else None,
                    deduction_points=deduction[1] if deduction else 0,
                )
            )
        elif evaluation.get("classification") == "weak":
            findings.append(
                _finding(
                    category="headers",
                    severity="warning",
                    key=f"{evaluation['name']}_weak",
                    title=f"{evaluation['name'].replace('-', ' ').title()} Weak",
                    description=evaluation.get("message") or "Security header is present but weak.",
                    observed_value=evaluation.get("observed_value") or "weak header value",
                    expected_value=evaluation.get("expected_value") or "Header should use a strong value",
                    evidence_source=evaluation.get("evidence_source") or "response headers",
                    module_name="header_checker",
                    recommendation=evaluation.get("recommendation") or "Tighten the header policy.",
                    confidence="high",
                )
            )

    if not email_security_snapshot.get("spf_present"):
        findings.append(
            _finding(
                category="email_security",
                severity="warning",
                key="spf_missing",
                title="SPF Missing",
                description="No SPF TXT record was found for the domain.",
                observed_value="No SPF record detected",
                expected_value="A TXT record that starts with v=spf1",
                evidence_source="dns TXT records",
                module_name="email_security_checker",
                recommendation="Publish an SPF record to make email spoofing harder.",
                confidence="high",
                deduction_key="spf_missing",
                deduction_points=5,
            )
        )

    if not email_security_snapshot.get("dmarc_present"):
        findings.append(
            _finding(
                category="email_security",
                severity="warning",
                key="dmarc_missing",
                title="DMARC Missing",
                description="No DMARC policy was found for the domain.",
                observed_value="No DMARC record detected",
                expected_value="A TXT record at _dmarc.<domain> with v=DMARC1",
                evidence_source="dns DMARC lookup",
                module_name="email_security_checker",
                recommendation="Publish a DMARC record so mailbox providers can act on spoofed mail.",
                confidence="high",
                deduction_key="dmarc_missing",
                deduction_points=5,
            )
        )
    elif email_security_snapshot.get("dmarc_policy") == "none":
        findings.append(
            _finding(
                category="email_security",
                severity="info",
                key="dmarc_monitoring_only",
                title="DMARC Monitoring Only",
                description="DMARC is present, but the policy is p=none, which monitors mail without enforcing quarantine or reject.",
                observed_value=email_security_snapshot.get("dmarc_value") or "p=none",
                expected_value="DMARC policy set to quarantine or reject when ready",
                evidence_source="dns DMARC lookup",
                module_name="email_security_checker",
                recommendation="Move DMARC from monitoring to enforcement after validating legitimate senders.",
                confidence="medium",
            )
        )

    if security_txt.get("status") == "partial":
        findings.append(
            _finding(
                category="public_files",
                severity="warning",
                key="invalid_security_txt",
                title="security.txt Looks Invalid",
                description="A security.txt path responded, but the body did not look like a valid security.txt file.",
                observed_value="; ".join(security_txt.get("validation_notes", [])) or "Malformed security.txt",
                expected_value="security.txt with Contact:, Expires:, and plain-text content",
                evidence_source="public file validation",
                module_name="public_files_checker",
                recommendation="Serve a plain-text security.txt file with contact details and expiry metadata.",
                confidence="high",
                deduction_key="invalid_security_txt",
                deduction_points=5,
            )
        )
    elif security_txt.get("status") == "not_found":
        findings.append(
            _finding(
                category="public_files",
                severity="info",
                key="security_txt_missing",
                title="security.txt Missing",
                description="No public security.txt file was found.",
                observed_value="security.txt not found",
                expected_value="/.well-known/security.txt available over HTTPS",
                evidence_source="public file validation",
                module_name="public_files_checker",
                recommendation="Add /.well-known/security.txt so researchers know how to contact you responsibly.",
                confidence="high",
            )
        )

    if robots_txt.get("status") == "partial":
        findings.append(
            _finding(
                category="public_files",
                severity="info",
                key="robots_txt_unusual",
                title="robots.txt Looks Unusual",
                description="robots.txt responded, but the body did not look like a standard robots file.",
                observed_value="; ".join(robots_txt.get("validation_notes", [])) or "Unexpected robots.txt content",
                expected_value="robots.txt with User-agent and Allow/Disallow directives",
                evidence_source="public file validation",
                module_name="public_files_checker",
                recommendation="Serve a plain-text robots.txt file if you intend to expose crawler guidance.",
                confidence="medium",
            )
        )

    if ct_snapshot.get("deduped_host_count"):
        findings.append(
            _finding(
                category="certificate_transparency",
                severity="info",
                key="ct_hostnames_discovered",
                title="Public Certificate Hostnames Discovered",
                description="Public certificate history shows additional hostnames tied to this domain.",
                observed_value=f"{ct_snapshot.get('deduped_host_count')} hostnames discovered",
                expected_value="Only intentionally exposed hostnames should appear in cert history",
                evidence_source="crt.sh certificate transparency lookup",
                module_name="ct_checker",
                recommendation="Review discovered subdomains and retire or secure any that should no longer be exposed.",
                confidence="medium",
            )
        )

    if fingerprint_snapshot.get("server_header"):
        findings.append(
            _finding(
                category="fingerprint",
                severity="info",
                key="server_header_exposed",
                title="Server Header Exposed",
                description="The site exposes a server banner that may reveal infrastructure clues.",
                observed_value=fingerprint_snapshot.get("server_header"),
                expected_value="Minimal or generic server banner exposure",
                evidence_source="homepage response headers",
                module_name="fingerprint_checker",
                recommendation="Minimize server banner exposure at the proxy or CDN layer when practical.",
                confidence="medium",
            )
        )

    https_latency = http_snapshot.get("metrics", {}).get("https_response_time_ms")
    if https_latency and https_latency >= 4000:
        findings.append(
            _finding(
                category="performance",
                severity="info",
                key="slow_https_response",
                title="Slow HTTPS Response",
                description="The HTTPS endpoint responded more slowly than expected during the scan.",
                observed_value=f"{https_latency} ms",
                expected_value="A responsive HTTPS endpoint with low latency",
                evidence_source="timing metrics",
                module_name="http_checker",
                recommendation="Review caching, CDN placement, and upstream response times.",
                confidence="medium",
            )
        )

    return findings
