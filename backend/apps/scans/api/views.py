import logging
from io import BytesIO

from django.http import FileResponse
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.reports.api.serializers import ReportSerializer
from apps.reports.services.pdf import PDFReportService
from apps.scans.models import ScanResult, Vulnerability
from apps.scans.services.github_push import GitHubPushError, GitHubPushService
from apps.scans.services.pipeline import ScanPipeline
from apps.scans.tasks import run_project_scan

from .serializers import ScanResultDetailSerializer, ScanResultListSerializer, VulnerabilitySerializer

logger = logging.getLogger(__name__)


class ScanResultViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    search_fields = ("project__name", "summary", "ai_summary", "status", "project__user__email")
    ordering_fields = ("started_at", "finished_at", "score", "vibe_score", "critical_count")
    ordering = ("-started_at",)

    def get_queryset(self):
        queryset = ScanResult.objects.select_related("project", "project__user").prefetch_related("vulnerabilities", "reports")
        if getattr(self.request.user, "role", None) != "admin":
            queryset = queryset.filter(project__user=self.request.user)
        project_id = self.request.query_params.get("project")
        status_value = self.request.query_params.get("status")
        trigger_type = self.request.query_params.get("trigger_type")
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        if status_value:
            queryset = queryset.filter(status=status_value)
        if trigger_type:
            queryset = queryset.filter(trigger_type=trigger_type)
        return queryset

    def get_serializer_class(self):
        return ScanResultDetailSerializer if self.action == "retrieve" else ScanResultListSerializer

    @action(detail=True, methods=["post"], url_path="rerun")
    def rerun(self, request, pk=None):
        scan = self.get_object()
        task = run_project_scan.delay(project_id=scan.project_id, trigger_type="manual", initiated_by_id=request.user.id)
        return Response({"detail": "Re-scan queued.", "task_id": task.id, "project_id": scan.project_id}, status=status.HTTP_202_ACCEPTED)

    @action(detail=True, methods=["post"], url_path="generate-report")
    def generate_report(self, request, pk=None):
        scan = self.get_object()
        report = PDFReportService().create_report_record(scan, f"scan-report-{scan.id}.pdf", force=True)
        return Response(ReportSerializer(report, context={"request": request}).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path="compare-report")
    def compare_report(self, request, pk=None):
        scan = self.get_object()
        suggestions = request.data.get("suggestions") or []
        if not isinstance(suggestions, list) or not suggestions:
            return Response({"detail": "Provide at least one compare suggestion to generate the PDF."}, status=status.HTTP_400_BAD_REQUEST)

        pdf_bytes = PDFReportService().generate_compare_pdf(scan, suggestions)
        filename = f"scan-{scan.id}-compare-report.pdf"
        logger.info("[compare-report] generated compare pdf scan_id=%s suggestions=%s", scan.id, len(suggestions))
        return FileResponse(BytesIO(pdf_bytes), as_attachment=True, filename=filename, content_type="application/pdf")

    @action(detail=True, methods=["post"], url_path="accept-and-push")
    def accept_and_push(self, request, pk=None):
        scan = self.get_object()
        request_body = dict(request.data)
        vulnerability_ids = request.data.get("vulnerability_ids") or request.data.get("files") or []
        commit_message = (request.data.get("commit_message") or "").strip()
        rerun_scan = str(request.data.get("rerun_scan", True)).lower() in {"true", "1", "yes"}

        logger.info("[accept-and-push] scan_id=%s user=%s body=%s", scan.id, getattr(request.user, "email", request.user.id), request_body)

        if scan.status != ScanResult.Status.SUCCESS:
            return Response({"status": "error", "message": "Only completed successful scans can push accepted code changes."}, status=status.HTTP_400_BAD_REQUEST)
        if not isinstance(vulnerability_ids, list) or not vulnerability_ids:
            return Response({"status": "error", "message": "Provide at least one accepted file or vulnerability id."}, status=status.HTTP_400_BAD_REQUEST)

        vulnerabilities = scan.vulnerabilities.filter(id__in=vulnerability_ids).exclude(file_path="")
        if not vulnerabilities.exists():
            return Response({"status": "error", "message": "No accepted code findings were found for push."}, status=status.HTTP_400_BAD_REQUEST)

        logger.info("[accept-and-push] resolved_vulnerabilities=%s", list(vulnerabilities.values_list("id", "file_path")))
        logger.info("[accept-and-push] commit_message=%s", commit_message or "<auto-generated>")
        logger.info("[accept-and-push] repo_targets=%s", scan.project.get_github_repositories())

        try:
            push_result = GitHubPushService(
                scan_result=scan,
                selected_vulnerabilities=vulnerabilities,
                commit_message=commit_message,
            ).execute()
        except GitHubPushError as exc:
            logger.exception("[accept-and-push] controlled push failure for scan_id=%s", scan.id)
            return Response({
                "status": "error",
                "message": str(exc),
                "detail": str(exc),
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as exc:
            logger.exception("[accept-and-push] unexpected push failure for scan_id=%s", scan.id)
            return Response({
                "status": "error",
                "message": f"Push failed: {exc}",
                "detail": f"Push failed: {exc}",
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response_payload = {
            "status": push_result.get("status") or "success",
            "message": push_result.get("message") or "Code pushed successfully",
            "detail": push_result.get("message") or "Code pushed successfully",
            "commit": push_result.get("commit"),
            "push_result": push_result,
        }

        if rerun_scan:
            try:
                rerun_result = ScanPipeline().run(project=scan.project, initiated_by=request.user)
                response_payload["scan_result"] = ScanResultDetailSerializer(rerun_result, context={"request": request}).data
            except Exception as exc:
                logger.exception("[accept-and-push] push succeeded but rerun failed for scan_id=%s", scan.id)
                response_payload["rerun_error"] = str(exc)

        logger.info("[accept-and-push] push successful scan_id=%s commit=%s files_updated=%s", scan.id, response_payload.get("commit"), len(push_result.get("changed_files") or []))
        return Response(response_payload, status=status.HTTP_200_OK)


class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = VulnerabilitySerializer
    permission_classes = [permissions.IsAuthenticated]
    search_fields = ("title", "category", "severity", "endpoint", "file_path")
    ordering_fields = ("created_at", "severity", "category")
    ordering = ("-created_at",)

    def get_queryset(self):
        queryset = Vulnerability.objects.select_related("scan_result", "scan_result__project", "scan_result__project__user")
        if getattr(self.request.user, "role", None) != "admin":
            queryset = queryset.filter(scan_result__project__user=self.request.user)
        scan_result_id = self.request.query_params.get("scan_result")
        severity = self.request.query_params.get("severity")
        category = self.request.query_params.get("category")
        if scan_result_id:
            queryset = queryset.filter(scan_result_id=scan_result_id)
        if severity:
            queryset = queryset.filter(severity=severity)
        if category:
            queryset = queryset.filter(category=category)
        return queryset
