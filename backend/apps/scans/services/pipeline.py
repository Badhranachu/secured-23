import logging

from django.utils import timezone

from apps.ai_core.services.ai_service import AIService
from apps.notifications.services.emailer import EmailService
from apps.projects.models import Project
from apps.scans.models import ScanResult, Vulnerability
from apps.surface_scan.models import DomainScan
from apps.surface_scan.services.orchestrator import SurfaceScanOrchestrator

from .api_endpoints import normalize_api_list
from .checks.api_checks import scan_api_endpoints
from .checks.auth_checks import authenticate_test_account
from .checks.credential_checks import evaluate_project_credentials
from .checks.github_checks import scan_github_repository
from .checks.helpers import build_finding
from .checks.jwt_checks import inspect_jwt_token
from .checks.vibe_checks import analyze_vibe_patterns
from .file_path_resolver import resolve_finding_file_paths
from .scoring import calculate_combined_security_score, calculate_security_score, calculate_vibe_risk_score, fallback_summary, summarize_findings

logger = logging.getLogger(__name__)


def _scan_progress(project, percent, stage, detail=""):
    label = f"[SCAN {project.id}:{project.name}] {int(percent):>3}% {stage}"
    if detail:
        label = f"{label} - {detail}"
    logger.info(label)


class ScanPipeline:
    BASIC_COMMON_ENDPOINTS = [
        "GET /api/health",
        "GET /health",
        "GET /openapi.json",
        "GET /swagger.json",
        "GET /api/login",
        "GET /api/profile",
        "GET /api/admin/users",
    ]

    ADVANCED_COMMON_ENDPOINTS = [
        "GET /api/health",
        "GET /health",
        "GET /openapi.json",
        "GET /swagger.json",
        "POST /login",
        "POST /api/login",
        "POST /auth/login",
        "POST /api/auth/login",
        "POST /token",
        "POST /auth/token",
        "GET /api/profile",
        "GET /api/users/me",
        "GET /api/v1/profile",
        "GET /api/admin/users",
        "GET /admin",
    ]

    def run(self, project: Project, initiated_by=None, trigger_type: str = ScanResult.TriggerType.MANUAL):
        started_at = timezone.now()
        result = ScanResult.objects.create(
            project=project,
            initiated_by=initiated_by,
            status=ScanResult.Status.RUNNING,
            trigger_type=trigger_type,
            started_at=started_at,
            summary="Scan started.",
            raw_json={"checks": []},
        )
        _scan_progress(project, 0, "scan started", f"mode={project.scan_mode}, trigger={trigger_type}")

        if project.scan_mode == Project.ScanMode.BASIC:
            return self._run_basic_surface_scan(project, result, initiated_by)

        try:
            findings = []
            raw_checks = []
            github_output = {"findings": [], "metadata": {"discovered_routes": [], "repos": []}, "code_samples": []}
            code_samples = []

            _scan_progress(project, 10, "surface scan", "starting public website/domain checks")
            surface_scan, surface_findings, surface_checks, surface_detail = self._run_surface_scan_capture(project, result)
            findings.extend(surface_findings)
            raw_checks.extend(surface_checks)
            _scan_progress(project, 35, "surface scan", f"status={(surface_scan.status if surface_scan else 'failed') if surface_scan else 'failed'}")

            if project.get_github_repositories():
                _scan_progress(project, 42, "github scan", "fetching repository contents and code signals")
                github_output = scan_github_repository(project)
                raw_checks.append({"name": "github_repository", "status": github_output.get("metadata", {}).get("overall_status", "not_available"), "metadata": github_output.get("metadata", {})})
                findings.extend(github_output.get("findings", []))
                code_samples = github_output.get("code_samples", [])
                _scan_progress(project, 52, "github scan", f"repos_scanned={github_output.get('metadata', {}).get('scanned_repo_count', 0)}, repos_failed={github_output.get('metadata', {}).get('failed_repo_count', 0)}, malware_signals={github_output.get('metadata', {}).get('malware_issue_count', 0)}")

            _scan_progress(project, 58, "endpoint inventory", "building candidate endpoint list")
            normalized_endpoints = self._build_endpoint_inventory(project, github_output)
            api_inventory_metadata = {
                "effective_api_base_url": project.get_effective_api_base_url(),
                "candidate_endpoint_count": len(normalized_endpoints),
                "candidate_endpoints": [{"method": item.method, "route": item.route, "url": item.url} for item in normalized_endpoints],
                "scan_mode": project.scan_mode,
                "inventory_source": "github_and_safe_defaults",
            }
            raw_checks.append({"name": "api_inventory", "status": "success", "metadata": api_inventory_metadata})
            _scan_progress(project, 64, "endpoint inventory", f"candidate_endpoints={len(normalized_endpoints)}")

            auth_output = {"findings": [], "metadata": {"attempted": False}, "token": None}
            if normalized_endpoints:
                _scan_progress(project, 70, "test auth", "checking whether a login token can be obtained")
                auth_output = authenticate_test_account(project, normalized_endpoints)
                findings.extend(auth_output.get("findings", []))
                raw_checks.append({"name": "test_auth", "status": auth_output.get("metadata", {}).get("status", "not_available"), "metadata": auth_output.get("metadata", {})})
                _scan_progress(project, 74, "test auth", f"status={auth_output.get('metadata', {}).get('status', 'not_available')}, attempted={auth_output.get('metadata', {}).get('attempted', False)}")

            credential_output = evaluate_project_credentials(project)
            findings.extend(credential_output.get("findings", []))
            raw_checks.append({"name": "credential_strength", "status": credential_output.get("metadata", {}).get("status", "not_available"), "metadata": credential_output.get("metadata", {})})

            token_to_check = auth_output.get("token") or project.get_token()
            jwt_output = {"findings": [], "metadata": {}}
            if token_to_check:
                _scan_progress(project, 78, "jwt inspection", "decoding discovered token")
                jwt_output = inspect_jwt_token(token_to_check)
                findings.extend(jwt_output.get("findings", []))
                raw_checks.append({"name": "jwt_token", "status": jwt_output.get("metadata", {}).get("status", "success"), "metadata": jwt_output.get("metadata", {})})

            if normalized_endpoints:
                _scan_progress(project, 82, "api probe", "probing discovered and default endpoints safely")
                api_output = scan_api_endpoints(project, normalized_endpoints, auth_context=auth_output)
                findings.extend(api_output.get("findings", []))
                raw_checks.append({"name": "api_endpoints", "status": "success", "metadata": api_output.get("metadata", {})})
                _scan_progress(project, 88, "api probe", f"working={api_output.get('metadata', {}).get('working_count', 0)}, public={api_output.get('metadata', {}).get('public_count', 0)}, protected={api_output.get('metadata', {}).get('protected_count', 0)}")
            else:
                api_output = {"metadata": {"endpoint_results": [], "working_endpoints": [], "count": 0, "working_count": 0, "public_count": 0, "protected_count": 0}}
                raw_checks.append({"name": "api_endpoints", "status": "not_available", "metadata": api_output.get("metadata", {})})

            if code_samples:
                _scan_progress(project, 91, "code heuristics", "checking for insecure AI-style and vibe-code patterns")
                vibe_output = analyze_vibe_patterns(project, code_samples)
                findings.extend(vibe_output.get("findings", []))
                raw_checks.append({"name": "vibe_code", "status": "success", "metadata": vibe_output.get("metadata", {})})
            else:
                vibe_output = {"findings": [], "metadata": {"sample_count": 0, "scanned_paths": []}}

            findings = resolve_finding_file_paths(findings, github_output, code_samples)
            malware_findings = [item for item in findings if item.get("category") == "github_malware"]
            malware_summary = {
                "detected": bool(malware_findings),
                "issue_count": len(malware_findings),
                "alert_sent": False,
                "top_titles": [item.get("title", "Suspicious malware signal") for item in malware_findings[:5]],
            }

            summary_data = summarize_findings(findings)
            combined_score = calculate_combined_security_score(
                findings,
                base_score=surface_scan.risk_score if surface_scan else 100,
                existing_breakdown=surface_detail.get("scoring_breakdown", []),
            )
            result.score = combined_score["score"]
            result.vibe_score = calculate_vibe_risk_score(findings)
            result.critical_count = summary_data["critical_count"]
            result.warning_count = summary_data["warning_count"]
            result.info_count = summary_data["info_count"]
            result.summary = fallback_summary(project.name, findings)
            result.raw_json = {
                "scan_mode": project.scan_mode,
                "checks": raw_checks,
                "endpoint_count": len(normalized_endpoints),
                "top_categories": summary_data["top_categories"],
                "scanned_at": timezone.now().isoformat(),
                "surface_scan_id": surface_scan.id if surface_scan else None,
                "surface_scan": surface_scan.raw_json if surface_scan else {},
                "detailed_report": {
                    **surface_detail,
                    "risk_level": combined_score["risk_level"],
                    "scoring_breakdown": combined_score["scoring_breakdown"],
                    "working_endpoints": api_output.get("metadata", {}).get("working_endpoints", []),
                    "endpoint_results": api_output.get("metadata", {}).get("endpoint_results", []),
                    "public_endpoints": api_output.get("metadata", {}).get("public_endpoints", []),
                    "protected_endpoints": api_output.get("metadata", {}).get("protected_endpoints", []),
                    "admin_accessible_with_token": api_output.get("metadata", {}).get("admin_accessible_with_token", []),
                    "discovered_routes": github_output.get("metadata", {}).get("discovered_routes", []),
                    "candidate_endpoints": api_inventory_metadata["candidate_endpoints"],
                    "effective_api_base_url": api_inventory_metadata["effective_api_base_url"],
                    "inventory_source": api_inventory_metadata["inventory_source"],
                    "github": github_output.get("metadata", {}),
                    "credential_security": credential_output.get("metadata", {}),
                    "malware_summary": malware_summary,
                    "authenticated_with_test_account": auth_output.get("metadata", {}).get("authenticated", False),
                },
            }

            _scan_progress(project, 95, "ai summary", "building the final narrative summary")
            try:
                ai_payload = AIService().generate_security_summary(project.name, self._findings_to_text(findings))
                result.ai_summary = ai_payload.get("content", "")
                result.provider_used = ai_payload.get("provider", "")
            except Exception as exc:
                logger.info("AI summary unavailable for project %s: %s", project.id, exc)

            result.status = ScanResult.Status.SUCCESS
            result.finished_at = timezone.now()
            result.next_run = project.refresh_next_scan(result.finished_at) if project.scan_enabled else None
            result.save()

            Vulnerability.objects.filter(scan_result=result).delete()
            Vulnerability.objects.bulk_create([
                Vulnerability(
                    scan_result=result,
                    category=item["category"],
                    severity=item["severity"],
                    title=item["title"],
                    description=item["description"],
                    endpoint=item.get("endpoint", ""),
                    file_path=item.get("file_path", ""),
                    recommendation=item.get("recommendation", ""),
                    evidence=item.get("evidence", {}),
                )
                for item in findings
            ])

            if malware_findings:
                try:
                    EmailService().send_malware_alert(project=project, scan_result=result, malware_findings=malware_findings)
                    (((result.raw_json or {}).get("detailed_report") or {}).get("malware_summary") or {}).update({"alert_sent": True})
                    result.save(update_fields=("raw_json", "updated_at"))
                except Exception as exc:
                    logger.warning("Malware alert email failed for project %s: %s", project.id, exc)

            project.last_scanned_at = result.finished_at
            project.next_scan_at = result.next_run
            project.save(update_fields=("last_scanned_at", "next_scan_at", "updated_at"))
            _scan_progress(project, 100, "scan complete", f"score={result.score}, findings={result.critical_count} critical / {result.warning_count} warning / {result.info_count} info")
            
            # Always trigger email summary on scan completion as requested
            try:
                EmailService().send_daily_summary(project=project, scan_result=result)
            except Exception as exc:
                logger.warning("Scan summary email failed for project %s: %s", project.id, exc)

            return result
        except Exception as exc:
            _scan_progress(project, 100, "scan failed", str(exc))
            logger.exception("Scan pipeline failed for project %s", project.id)
            result.status = ScanResult.Status.FAILED
            result.finished_at = timezone.now()
            result.failure_reason = str(exc)
            result.summary = "Scan execution failed before all checks completed."
            result.raw_json = {"checks": locals().get("raw_checks", []), "error": str(exc)}
            result.next_run = project.refresh_next_scan(result.finished_at) if project.scan_enabled else None
            result.save(update_fields=("status", "finished_at", "failure_reason", "summary", "raw_json", "next_run", "updated_at"))
            project.next_scan_at = result.next_run
            project.save(update_fields=("next_scan_at", "updated_at"))
            return result

    def _run_basic_surface_scan(self, project, result, initiated_by):
        try:
            _scan_progress(project, 10, "surface scan", "starting basic public website/domain checks")
            surface_scan = DomainScan.objects.create(
                user=project.user,
                project=project,
                scan_result=result,
                domain=project.domain,
                normalized_domain=project.domain,
                status=DomainScan.Status.PENDING,
                started_at=result.started_at,
            )
            SurfaceScanOrchestrator().run(surface_scan)
            surface_scan.refresh_from_db()
            _scan_progress(project, 92, "surface scan", f"status={surface_scan.status}")
            if surface_scan.status != DomainScan.Status.SUCCESS:
                raise RuntimeError(surface_scan.error_message or surface_scan.summary or "Surface scan failed")

            findings = self._surface_scan_findings(surface_scan)
            summary_data = summarize_findings(findings)
            risk_payload = (surface_scan.raw_json or {}).get("risk", {})
            detailed_report = {
                "normalized_domain": surface_scan.normalized_domain,
                "dns": surface_scan.dns_json,
                "dns_status": surface_scan.dns_status_json,
                "redirects": surface_scan.redirect_chain_json,
                "headers": surface_scan.headers_json,
                "tls": (surface_scan.raw_json or {}).get("tls", {}),
                "tls_status": surface_scan.tls_status_json,
                "certificate_transparency": surface_scan.subdomains_json,
                "ct_status": surface_scan.ct_status_json,
                "public_files": surface_scan.public_files_json,
                "public_file_validation": surface_scan.public_file_validation_json,
                "fingerprint": surface_scan.fingerprint_json,
                "timing": surface_scan.timing_json,
                "email_security": surface_scan.email_security_json,
                "top_findings": risk_payload.get("top_findings", []),
                "recommendations": risk_payload.get("top_recommendations", []),
                "risk_level": surface_scan.risk_level,
                "scoring_breakdown": risk_payload.get("scoring_breakdown", []),
            }

            result.status = ScanResult.Status.SUCCESS
            result.finished_at = timezone.now()
            result.score = surface_scan.risk_score
            result.vibe_score = 0
            result.critical_count = summary_data["critical_count"]
            result.warning_count = summary_data["warning_count"]
            result.info_count = summary_data["info_count"]
            result.summary = surface_scan.summary
            result.ai_summary = surface_scan.ai_summary
            result.provider_used = surface_scan.ai_provider
            result.next_run = project.refresh_next_scan(result.finished_at) if project.scan_enabled else None
            result.raw_json = {
                "scan_mode": project.scan_mode,
                "checks": (surface_scan.raw_json or {}).get("checks", []),
                "top_categories": summary_data["top_categories"],
                "scanned_at": result.finished_at.isoformat(),
                "surface_scan_id": surface_scan.id,
                "surface_scan": surface_scan.raw_json,
                "detailed_report": detailed_report,
            }
            result.save()

            Vulnerability.objects.filter(scan_result=result).delete()
            Vulnerability.objects.bulk_create([
                Vulnerability(
                    scan_result=result,
                    category=item["category"],
                    severity=item["severity"],
                    title=item["title"],
                    description=item["description"],
                    endpoint=item.get("endpoint", ""),
                    recommendation=item.get("recommendation", ""),
                    evidence=item.get("evidence", {}),
                )
                for item in findings
            ])

            project.last_scanned_at = result.finished_at
            project.next_scan_at = result.next_run
            project.save(update_fields=("last_scanned_at", "next_scan_at", "updated_at"))
            _scan_progress(project, 100, "scan complete", f"score={result.score}, findings={result.critical_count} critical / {result.warning_count} warning / {result.info_count} info")
            
            # Always trigger email summary on scan completion as requested
            try:
                EmailService().send_daily_summary(project=project, scan_result=result)
            except Exception as exc:
                logger.warning("Scan summary email failed for project %s: %s", project.id, exc)

            return result
        except Exception as exc:
            _scan_progress(project, 100, "scan failed", str(exc))
            logger.exception("Basic surface scan failed for project %s", project.id)
            result.status = ScanResult.Status.FAILED
            result.finished_at = timezone.now()
            result.failure_reason = str(exc)
            result.summary = "Domain-only surface scan failed before all checks completed."
            result.raw_json = {"checks": [], "error": str(exc), "scan_mode": project.scan_mode}
            result.next_run = project.refresh_next_scan(result.finished_at) if project.scan_enabled else None
            result.save(update_fields=("status", "finished_at", "failure_reason", "summary", "raw_json", "next_run", "updated_at"))
            project.next_scan_at = result.next_run
            project.save(update_fields=("next_scan_at", "updated_at"))
            return result

    def _run_surface_scan_capture(self, project, result):
        try:
            surface_scan = DomainScan.objects.create(
                user=project.user,
                project=project,
                scan_result=result,
                domain=project.domain,
                normalized_domain=project.domain,
                status=DomainScan.Status.PENDING,
                started_at=result.started_at,
            )
            SurfaceScanOrchestrator().run(surface_scan)
            surface_scan.refresh_from_db()
            if surface_scan.status != DomainScan.Status.SUCCESS:
                warning = build_finding(
                    "surface_scan",
                    "warning",
                    "Website surface scan did not complete",
                    surface_scan.error_message or surface_scan.summary or "AEGIS AI could not complete the public website/domain scan.",
                    endpoint=project.domain,
                    recommendation="Verify the target is reachable and try the scan again.",
                )
                check = {
                    "name": "surface_scan",
                    "status": "failed",
                    "metadata": {
                        "normalized_domain": surface_scan.normalized_domain,
                        "error_message": surface_scan.error_message,
                        "summary": surface_scan.summary,
                    },
                }
                return surface_scan, [warning], [check], {}

            risk_payload = (surface_scan.raw_json or {}).get("risk", {})
            detailed_report = {
                "normalized_domain": surface_scan.normalized_domain,
                "dns": surface_scan.dns_json,
                "dns_status": surface_scan.dns_status_json,
                "redirects": surface_scan.redirect_chain_json,
                "headers": surface_scan.headers_json,
                "tls": (surface_scan.raw_json or {}).get("tls", {}),
                "tls_status": surface_scan.tls_status_json,
                "certificate_transparency": surface_scan.subdomains_json,
                "ct_status": surface_scan.ct_status_json,
                "public_files": surface_scan.public_files_json,
                "public_file_validation": surface_scan.public_file_validation_json,
                "fingerprint": surface_scan.fingerprint_json,
                "timing": surface_scan.timing_json,
                "email_security": surface_scan.email_security_json,
                "top_findings": risk_payload.get("top_findings", []),
                "recommendations": risk_payload.get("top_recommendations", []),
                "risk_level": surface_scan.risk_level,
                "scoring_breakdown": risk_payload.get("scoring_breakdown", []),
            }
            return surface_scan, self._surface_scan_findings(surface_scan), (surface_scan.raw_json or {}).get("checks", []), detailed_report
        except Exception as exc:
            warning = build_finding(
                "surface_scan",
                "warning",
                "Website surface scan could not start",
                f"AEGIS AI could not start the public website/domain scan: {exc}",
                endpoint=project.domain,
                recommendation="Verify the target is reachable and try again.",
            )
            check = {"name": "surface_scan", "status": "failed", "metadata": {"error_message": str(exc)}}
            return None, [warning], [check], {}

    def _surface_scan_findings(self, surface_scan):
        findings = []
        endpoint = surface_scan.final_url or surface_scan.normalized_domain
        for item in surface_scan.findings.all():
            findings.append(
                {
                    "category": item.category,
                    "severity": item.severity,
                    "title": item.key.replace("_", " ").title(),
                    "description": item.description,
                    "endpoint": endpoint,
                    "recommendation": item.recommendation,
                    "evidence": {
                        **(item.evidence or {}),
                        "observed_value": item.observed_value,
                        "expected_value": item.expected_value,
                        "evidence_source": item.evidence_source,
                        "confidence": item.confidence,
                        "module_name": item.module_name,
                    },
                }
            )
        return findings

    def _build_endpoint_inventory(self, project, github_output):
        effective_api_base_url = project.get_effective_api_base_url()
        if not effective_api_base_url:
            return []

        raw_lines = []
        defaults = self.BASIC_COMMON_ENDPOINTS if project.scan_mode == Project.ScanMode.BASIC else self.ADVANCED_COMMON_ENDPOINTS
        raw_lines.extend(defaults)

        if project.scan_mode == Project.ScanMode.BASIC and project.api_list:
            raw_lines.extend([line.strip() for line in project.api_list.splitlines() if line.strip()])

        if project.scan_mode in {Project.ScanMode.ADVANCED, Project.ScanMode.SERVER}:
            for route_info in github_output.get("metadata", {}).get("discovered_routes", []):
                raw_lines.append(f"{route_info.get('method', 'GET')} {route_info.get('route', '')}")

        unique_lines = []
        seen = set()
        for line in raw_lines:
            normalized = " ".join(line.split())
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            unique_lines.append(normalized)

        return normalize_api_list(effective_api_base_url, "\n".join(unique_lines))

    def _findings_to_text(self, findings):
        if not findings:
            return "No findings recorded."
        lines = []
        for item in findings[:30]:
            location = item.get("endpoint") or item.get("file_path") or "general"
            lines.append(f"[{item['severity'].upper()}] {item['title']} ({item['category']}) at {location}: {item['description']}")
        return "\n".join(lines)

