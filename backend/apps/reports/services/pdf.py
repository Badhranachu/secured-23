from io import BytesIO

from django.core.files.base import ContentFile
from django.template.loader import render_to_string
from django.utils import timezone

from apps.reports.models import Report


class PDFReportService:
    def generate(self, scan_result):
        try:
            return self._generate_with_weasyprint(scan_result)
        except Exception:
            return self._generate_with_reportlab(scan_result)

    def _get_report_context(self, scan_result):
        raw_json = scan_result.raw_json or {}
        detailed_report = raw_json.get("detailed_report", {})
        vulnerabilities = list(scan_result.vulnerabilities.all())
        github_summary = detailed_report.get("github", {})
        surface_scan = raw_json.get("surface_scan", {})
        risk_payload = surface_scan.get("risk", {})

        return {
            "project": scan_result.project,
            "scan_result": scan_result,
            "generated_at": timezone.now(),
            "detailed_report": detailed_report,
            "surface_scan": surface_scan,
            "github_summary": github_summary,
            "checks": raw_json.get("checks", []),
            "working_endpoints": detailed_report.get("working_endpoints", []),
            "discovered_routes": detailed_report.get("discovered_routes", []),
            "candidate_endpoints": detailed_report.get("candidate_endpoints", []),
            "endpoint_results": detailed_report.get("endpoint_results", []),
            "recommendations": detailed_report.get("recommendations", []) or risk_payload.get("top_recommendations", []),
            "top_findings": detailed_report.get("top_findings", []) or risk_payload.get("top_findings", []),
            "scoring_breakdown": detailed_report.get("scoring_breakdown", []) or risk_payload.get("scoring_breakdown", []),
            "vulnerabilities": vulnerabilities,
        }

    def _generate_with_reportlab(self, scan_result):
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        context = self._get_report_context(scan_result)
        detailed_report = context["detailed_report"]
        working_endpoints = context["working_endpoints"]
        discovered_routes = context["discovered_routes"]
        endpoint_results = context["endpoint_results"]
        vulnerabilities = context["vulnerabilities"]
        recommendations = context["recommendations"]
        top_findings = context["top_findings"]
        github_summary = context["github_summary"]

        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        left = 46
        right = width - 46
        max_width = right - left
        y = height - 46

        def new_page():
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            return height - 46

        def write_lines(y_value, text_value, font_name="Helvetica", font_size=10, gap=6):
            pdf.setFont(font_name, font_size)
            for raw_line in str(text_value).splitlines() or [""]:
                line = raw_line or " "
                segments = []
                while line:
                    probe = line
                    while pdf.stringWidth(probe, font_name, font_size) > max_width and " " in probe:
                        probe = probe.rsplit(" ", 1)[0]
                    if pdf.stringWidth(probe, font_name, font_size) > max_width:
                        probe = probe[:120]
                    segments.append(probe)
                    line = line[len(probe):].lstrip()
                if not segments:
                    segments = [" "]
                for segment in segments:
                    if y_value < 64:
                        y_value = new_page()
                        pdf.setFont(font_name, font_size)
                    pdf.drawString(left, y_value, segment[:180])
                    y_value -= 14
            return y_value - gap

        y = write_lines(y, f"AEGIS AI Security Report - {scan_result.project.name}", font_name="Helvetica-Bold", font_size=18, gap=8)
        y = write_lines(y, f"Generated: {timezone.now().isoformat()}", gap=2)
        y = write_lines(y, f"Status: {scan_result.status}", gap=2)
        y = write_lines(y, f"Score: {scan_result.score}", gap=2)
        y = write_lines(y, f"Vibe Risk: {scan_result.vibe_score}", gap=2)
        y = write_lines(y, f"Critical: {scan_result.critical_count} | Warnings: {scan_result.warning_count} | Info: {scan_result.info_count}", gap=6)
        y = write_lines(y, scan_result.ai_summary or scan_result.summary or "No summary available.", gap=10)

        overview = [
            f"Mode: {(scan_result.raw_json or {}).get('scan_mode', 'n/a')}",
            f"API Base: {detailed_report.get('effective_api_base_url', 'n/a')}",
            f"Candidate Endpoints: {len(context['candidate_endpoints'])}",
            f"Working Endpoints: {len(working_endpoints)}",
            f"Discovered Routes: {len(discovered_routes)}",
            f"GitHub Status: {github_summary.get('overall_status', 'not_available')}",
            f"GitHub Files Scanned: {github_summary.get('scanned_file_count', 0)}",
        ]
        y = write_lines(y, "Execution Overview", font_name="Helvetica-Bold", font_size=13, gap=4)
        for line in overview:
            y = write_lines(y, line, gap=2)

        if top_findings:
            y = write_lines(y, "Top Findings", font_name="Helvetica-Bold", font_size=13, gap=4)
            for item in top_findings[:10]:
                text = item if isinstance(item, str) else f"- {item.get('title', 'Finding')}: {item.get('description', '')}"
                y = write_lines(y, text, gap=2)

        if recommendations:
            y = write_lines(y, "Recommendations", font_name="Helvetica-Bold", font_size=13, gap=4)
            for item in recommendations[:10]:
                text = item if isinstance(item, str) else item.get("recommendation") or item.get("description") or "Recommendation recorded."
                y = write_lines(y, f"- {text}", gap=2)

        if endpoint_results:
            y = write_lines(y, "Endpoint Results", font_name="Helvetica-Bold", font_size=13, gap=4)
            for endpoint in endpoint_results[:15]:
                line = f"- {endpoint.get('declared_method', endpoint.get('method', 'GET'))} {endpoint.get('route', '')} | public={endpoint.get('unauth_status', 'n/a')} | token={endpoint.get('auth_status', 'n/a')} | {endpoint.get('classification', 'n/a')}"
                y = write_lines(y, line, gap=2)

        if discovered_routes:
            y = write_lines(y, "Discovered Routes", font_name="Helvetica-Bold", font_size=13, gap=4)
            for route in discovered_routes[:15]:
                line = f"- {route.get('method', 'GET')} {route.get('route', '')} ({route.get('source', 'source unknown')})"
                y = write_lines(y, line, gap=2)

        if vulnerabilities:
            y = write_lines(y, "Findings", font_name="Helvetica-Bold", font_size=13, gap=4)
            for vulnerability in vulnerabilities[:20]:
                line = f"- [{vulnerability.severity.upper()}] {vulnerability.title} | category={vulnerability.category} | endpoint={vulnerability.endpoint or '-'} | file={vulnerability.file_path or '-'}"
                y = write_lines(y, line, gap=2)
                if vulnerability.recommendation:
                    y = write_lines(y, f"  Recommendation: {vulnerability.recommendation}", gap=2)

        pdf.save()
        buffer.seek(0)
        return buffer.read()

    def _generate_with_weasyprint(self, scan_result):
        from weasyprint import HTML

        html = render_to_string("reports/scan_report.html", self._get_report_context(scan_result))
        return HTML(string=html).write_pdf()

    def create_report_record(self, scan_result, filename: str, force=False):
        existing = Report.objects.filter(scan_result=scan_result).order_by("-generated_at").first()
        pdf_content = self.generate(scan_result)
        if existing:
            existing.pdf_file.save(filename, ContentFile(pdf_content), save=True)
            return existing
        report = Report.objects.create(project=scan_result.project, scan_result=scan_result)
        report.pdf_file.save(filename, ContentFile(pdf_content), save=True)
        return report

    def generate_compare_pdf(self, scan_result, suggestions):
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        left = 42
        top = height - 46
        line_height = 14
        code_line_height = 11
        max_width = width - (left * 2)

        def new_page():
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            return top

        def write_block(y, text_value, font_name="Helvetica", font_size=10, indent=0, gap=6, code=False):
            nonlocal max_width
            if text_value is None:
                text_value = ""
            raw_lines = str(text_value).splitlines() or [""]
            effective_width = max_width - indent
            current_height = code_line_height if code else line_height
            pdf.setFont(font_name, font_size)
            for raw_line in raw_lines:
                wrapped = []
                line = raw_line or " "
                while line:
                    probe = line
                    while pdf.stringWidth(probe, font_name, font_size) > effective_width and " " in probe:
                        probe = probe.rsplit(" ", 1)[0]
                    if pdf.stringWidth(probe, font_name, font_size) > effective_width and len(probe) > 110:
                        probe = probe[:110]
                    wrapped.append(probe)
                    line = line[len(probe):].lstrip()
                    if not line and raw_line == "":
                        break
                if not wrapped:
                    wrapped = [" "]
                for segment in wrapped:
                    if y < 70:
                        y = new_page()
                        pdf.setFont(font_name, font_size)
                    pdf.drawString(left + indent, y, segment[:180])
                    y -= current_height
            return y - gap

        y = top
        pdf.setTitle(f"AEGIS AI Compare Report - {scan_result.project.name}")
        y = write_block(y, "AEGIS AI Compare Report", font_name="Helvetica-Bold", font_size=18, gap=10)
        y = write_block(y, f"Project: {scan_result.project.name}", font_name="Helvetica-Bold", font_size=11, gap=2)
        y = write_block(y, f"Scan ID: {scan_result.id}", gap=2)
        y = write_block(y, f"Generated: {timezone.now().isoformat()}", gap=10)
        y = write_block(y, "This PDF compares the current code posture with the recommended secure update, so another reviewer or AI tool can understand the issue quickly.", gap=12)

        for index, item in enumerate(suggestions, start=1):
            if y < 120:
                y = new_page()
            severity = str(item.get("severity") or "info").upper()
            y = write_block(y, f"Issue {index}: {item.get('title') or 'Recommended security change'}", font_name="Helvetica-Bold", font_size=13, gap=4)
            y = write_block(y, f"Severity: {severity}", font_name="Helvetica-Bold", gap=2)
            y = write_block(y, f"Target: {item.get('target') or 'Not available'}", gap=2)
            y = write_block(y, f"Surface: {item.get('surface') or 'Application file'}", gap=6)
            y = write_block(y, f"Summary: {item.get('summary') or 'No summary recorded.'}", gap=4)
            y = write_block(y, f"Advantage: {item.get('advantage') or 'Not recorded.'}", gap=4)
            y = write_block(y, f"Risk if unchanged: {item.get('downside') or 'Not recorded.'}", gap=8)
            y = write_block(y, "Old code", font_name="Helvetica-Bold", gap=4)
            y = write_block(y, item.get('diffBefore') or 'Not available.', font_name="Courier", font_size=8, indent=8, gap=8, code=True)
            y = write_block(y, "Recommended code", font_name="Helvetica-Bold", gap=4)
            y = write_block(y, item.get('diffAfter') or 'Not available.', font_name="Courier", font_size=8, indent=8, gap=12, code=True)

        pdf.save()
        buffer.seek(0)
        return buffer.read()
