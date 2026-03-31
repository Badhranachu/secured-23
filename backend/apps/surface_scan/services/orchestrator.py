import logging

from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.surface_scan.models import DomainFinding, DomainScan
from apps.surface_scan.services.ai_summary import DomainAISummaryService
from apps.surface_scan.services.ct_checker import discover_ct_subdomains
from apps.surface_scan.services.dns_checker import collect_dns_snapshot
from apps.surface_scan.services.domain_normalizer import DomainNormalizationError, normalize_domain_input
from apps.surface_scan.services.email_security_checker import analyze_email_security
from apps.surface_scan.services.findings_builder import build_surface_findings
from apps.surface_scan.services.fingerprint_checker import detect_fingerprint
from apps.surface_scan.services.header_checker import evaluate_security_headers
from apps.surface_scan.services.http_checker import check_http_reachability
from apps.surface_scan.services.public_files_checker import inspect_public_files
from apps.surface_scan.services.risk_scoring import calculate_surface_risk
from apps.surface_scan.services.timing_utils import timer_start, elapsed_ms
from apps.surface_scan.services.tls_checker import inspect_tls

logger = logging.getLogger(__name__)


def _surface_progress(scan, percent, stage, detail=""):
    label = f"[SURFACE {scan.id}:{scan.domain}] {int(percent):>3}% {stage}"
    if detail:
        label = f"{label} - {detail}"
    logger.info(label)


class SurfaceScanOrchestrator:
    def run(self, scan_or_id):
        scan = scan_or_id if isinstance(scan_or_id, DomainScan) else DomainScan.objects.select_related("user", "project", "scan_result").get(pk=scan_or_id)
        scan.status = DomainScan.Status.RUNNING
        scan.started_at = scan.started_at or timezone.now()
        scan.error_message = ""
        scan.save(update_fields=("status", "started_at", "error_message", "updated_at"))
        _surface_progress(scan, 0, "surface scan started")

        scan_started = timer_start()
        try:
            _surface_progress(scan, 8, "normalize target")
            normalized = normalize_domain_input(scan.domain)
            _surface_progress(scan, 18, "dns lookup", f"target={normalized}")
            dns_snapshot = collect_dns_snapshot(normalized)
            _surface_progress(scan, 34, "http/https reachability")
            http_snapshot = check_http_reachability(normalized)
            _surface_progress(scan, 44, "security headers")
            header_snapshot = evaluate_security_headers(http_snapshot.get("selected_headers", {}), https_reachable=http_snapshot.get("https", {}).get("reachable", False))
            _surface_progress(scan, 56, "tls inspection")
            tls_snapshot = inspect_tls(normalized)
            _surface_progress(scan, 66, "certificate transparency")
            ct_snapshot = discover_ct_subdomains(normalized)
            _surface_progress(scan, 76, "public files and homepage")
            public_files_snapshot = inspect_public_files(normalized, http_snapshot)
            _surface_progress(scan, 84, "fingerprinting")
            fingerprint_snapshot = detect_fingerprint(normalized, dns_snapshot, http_snapshot, public_files_snapshot)
            _surface_progress(scan, 88, "email security")
            email_security_snapshot = analyze_email_security(dns_snapshot)
            _surface_progress(scan, 92, "findings and scoring")
            findings = build_surface_findings(
                normalized,
                dns_snapshot,
                http_snapshot,
                header_snapshot,
                tls_snapshot,
                ct_snapshot,
                public_files_snapshot,
                fingerprint_snapshot,
                email_security_snapshot,
            )
            score_bundle = calculate_surface_risk(normalized, findings)
            timing_snapshot = {
                "dns_resolution_time_ms": dns_snapshot.get("total_lookup_time_ms"),
                "http_response_time_ms": http_snapshot.get("metrics", {}).get("http_response_time_ms"),
                "https_response_time_ms": http_snapshot.get("metrics", {}).get("https_response_time_ms"),
                "http_ttfb_ms": http_snapshot.get("metrics", {}).get("http_ttfb_ms"),
                "https_ttfb_ms": http_snapshot.get("metrics", {}).get("https_ttfb_ms"),
                "redirect_resolution_time_ms": http_snapshot.get("metrics", {}).get("redirect_resolution_time_ms"),
                "tls_lookup_time_ms": tls_snapshot.get("lookup_time_ms"),
                "total_scan_time_ms": elapsed_ms(scan_started),
            }
            _surface_progress(scan, 96, "ai summary")
            ai_payload = DomainAISummaryService().generate(
                normalized,
                dns_snapshot,
                http_snapshot,
                header_snapshot,
                tls_snapshot,
                ct_snapshot,
                public_files_snapshot,
                fingerprint_snapshot,
                email_security_snapshot,
                timing_snapshot,
                score_bundle,
            )

            checks = [
                {"name": "domain_normalization", "status": "success", "metadata": {"normalized_domain": normalized}},
                {"name": "dns_information", "status": dns_snapshot.get("status"), "metadata": {**dns_snapshot.get("summary", {}), "host_lookup_name": dns_snapshot.get("hostname"), "zone_lookup_name": dns_snapshot.get("zone_hostname")}},
                {
                    "name": "http_https",
                    "status": http_snapshot.get("status"),
                    "metadata": {
                        "http_status": http_snapshot.get("http", {}).get("status_code"),
                        "https_status": http_snapshot.get("https", {}).get("status_code"),
                        "final_url": http_snapshot.get("final_url"),
                        "preferred_scheme": http_snapshot.get("preferred_scheme"),
                        "redirect_count": http_snapshot.get("redirect_analysis", {}).get("redirect_count"),
                    },
                },
                {"name": "security_headers", "status": header_snapshot.get("status"), "metadata": header_snapshot.get("summary", {})},
                {
                    "name": "tls_information",
                    "status": tls_snapshot.get("status"),
                    "metadata": {
                        "issuer": tls_snapshot.get("issuer_name"),
                        "tls_version": tls_snapshot.get("tls_version"),
                        "days_to_expiry": tls_snapshot.get("days_to_expiry"),
                        "ssl_grade": tls_snapshot.get("ssl_grade"),
                        "hostname_match": tls_snapshot.get("hostname_match"),
                    },
                },
                {
                    "name": "certificate_transparency",
                    "status": ct_snapshot.get("status"),
                    "metadata": {"count": ct_snapshot.get("deduped_host_count", 0), "lookup_status": ct_snapshot.get("ct_lookup_status")},
                },
                {
                    "name": "public_files",
                    "status": public_files_snapshot.get("status"),
                    "metadata": {
                        "available_files": [key for key, value in public_files_snapshot.get("files", {}).items() if value.get("status") == "success"],
                        "title": public_files_snapshot.get("homepage", {}).get("title", ""),
                    },
                },
                {
                    "name": "email_security",
                    "status": email_security_snapshot.get("status"),
                    "metadata": {
                        "mx_present": email_security_snapshot.get("mx_present"),
                        "spf_present": email_security_snapshot.get("spf_present"),
                        "dmarc_present": email_security_snapshot.get("dmarc_present"),
                        "email_spoofing_risk": email_security_snapshot.get("email_spoofing_risk"),
                    },
                },
                {
                    "name": "fingerprinting",
                    "status": fingerprint_snapshot.get("status"),
                    "metadata": {
                        "server_header": fingerprint_snapshot.get("server_header"),
                        "hosting_clues": fingerprint_snapshot.get("hosting_clues", []),
                        "confidence": fingerprint_snapshot.get("fingerprint_confidence"),
                    },
                },
            ]

            scan.normalized_domain = normalized
            scan.status = DomainScan.Status.SUCCESS
            scan.finished_at = timezone.now()
            scan.http_status = http_snapshot.get("http", {}).get("status_code")
            scan.https_status = http_snapshot.get("https", {}).get("status_code")
            scan.final_url = http_snapshot.get("final_url", "")
            scan.ssl_grade = tls_snapshot.get("ssl_grade", "")
            scan.certificate_issuer = tls_snapshot.get("issuer_name") or ""
            scan.certificate_expiry = parse_datetime(tls_snapshot.get("certificate_expiry")) if tls_snapshot.get("certificate_expiry") else None
            scan.days_to_expiry = tls_snapshot.get("days_to_expiry")
            scan.dns_json = dns_snapshot
            scan.dns_status_json = {
                "status": dns_snapshot.get("status"),
                "summary": dns_snapshot.get("summary", {}),
                "errors": dns_snapshot.get("errors", {}),
            }
            scan.headers_json = header_snapshot
            scan.redirect_chain_json = http_snapshot.get("redirect_analysis", {})
            scan.tls_status_json = {
                "status": tls_snapshot.get("status"),
                "ssl_grade_status": tls_snapshot.get("ssl_grade_status"),
                "hostname_match": tls_snapshot.get("hostname_match"),
                "chain_validation_status": tls_snapshot.get("chain_validation_status"),
                "error_message": tls_snapshot.get("error_message"),
            }
            scan.subdomains_json = ct_snapshot
            scan.ct_status_json = {
                "status": ct_snapshot.get("status"),
                "ct_lookup_status": ct_snapshot.get("ct_lookup_status"),
                "raw_host_count": ct_snapshot.get("raw_host_count"),
                "deduped_host_count": ct_snapshot.get("deduped_host_count"),
            }
            scan.public_files_json = public_files_snapshot
            scan.public_file_validation_json = public_files_snapshot.get("files", {})
            scan.fingerprint_json = fingerprint_snapshot
            scan.timing_json = timing_snapshot
            scan.email_security_json = email_security_snapshot
            scan.risk_score = score_bundle["score"]
            scan.risk_level = score_bundle["risk_level"]
            scan.summary = score_bundle["summary"]
            scan.ai_summary = ai_payload.get("content", "")
            scan.ai_provider = ai_payload.get("provider", "")
            scan.raw_json = {
                "normalized_domain": normalized,
                "checks": checks,
                "dns": dns_snapshot,
                "reachability": http_snapshot,
                "redirects": http_snapshot.get("redirect_analysis", {}),
                "headers": header_snapshot,
                "tls": tls_snapshot,
                "certificate_transparency": ct_snapshot,
                "public_files": public_files_snapshot,
                "fingerprint": fingerprint_snapshot,
                "email_security": email_security_snapshot,
                "timing": timing_snapshot,
                "risk": {k: v for k, v in score_bundle.items() if k != "findings"},
            }
            scan.save()
            _surface_progress(scan, 99, "persisting results", f"risk_score={scan.risk_score}, risk_level={scan.risk_level}")

            scan.findings.all().delete()
            DomainFinding.objects.bulk_create(
                [
                    DomainFinding(
                        scan=scan,
                        category=item["category"],
                        severity=item["severity"],
                        key=item["key"],
                        value=item.get("observed_value", ""),
                        observed_value=item.get("observed_value", ""),
                        expected_value=item.get("expected_value", ""),
                        evidence_source=item.get("evidence_source", ""),
                        confidence=item.get("confidence", ""),
                        module_name=item.get("module_name", ""),
                        description=item["description"],
                        recommendation=item.get("recommendation", ""),
                        evidence=item.get("evidence", {}),
                    )
                    for item in score_bundle.get("findings", [])
                ]
            )
            _surface_progress(scan, 100, "surface scan complete", f"risk_score={scan.risk_score}, findings={len(score_bundle.get('findings', []))}")
            return scan.id
        except DomainNormalizationError as exc:
            _surface_progress(scan, 100, "surface scan failed", str(exc))
            scan.status = DomainScan.Status.FAILED
            scan.finished_at = timezone.now()
            scan.error_message = str(exc)
            scan.summary = "The supplied domain is not a valid public hostname."
            scan.save(update_fields=("status", "finished_at", "error_message", "summary", "updated_at"))
            return scan.id
        except Exception as exc:
            _surface_progress(scan, 100, "surface scan failed", str(exc))
            scan.status = DomainScan.Status.FAILED
            scan.finished_at = timezone.now()
            scan.error_message = str(exc)
            scan.summary = "The surface scan failed before all public checks completed."
            scan.save(update_fields=("status", "finished_at", "error_message", "summary", "updated_at"))
            return scan.id
