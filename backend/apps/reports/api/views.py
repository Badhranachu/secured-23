from django.http import FileResponse
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.reports.models import Report
from apps.reports.services.pdf import PDFReportService
from apps.scans.models import ScanResult

from .serializers import ReportSerializer


class ReportViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ReportSerializer
    permission_classes = [permissions.IsAuthenticated]
    ordering = ("-generated_at",)

    def get_queryset(self):
        queryset = Report.objects.select_related("project", "project__user", "scan_result")
        if getattr(self.request.user, "role", None) != "admin":
            queryset = queryset.filter(project__user=self.request.user)
        project_id = self.request.query_params.get("project")
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        return queryset

    @action(detail=True, methods=["get"], url_path="download")
    def download(self, request, pk=None):
        report = self.get_object()
        if not report.pdf_file:
            return Response({"detail": "PDF file not available for this report."}, status=status.HTTP_404_NOT_FOUND)
        return FileResponse(report.pdf_file.open("rb"), as_attachment=True, filename=report.pdf_file.name.split("/")[-1])

    @action(detail=False, methods=["post"], url_path="generate")
    def generate(self, request):
        scan_result_id = request.data.get("scan_result")
        project_id = request.data.get("project")
        scan_result = None
        if scan_result_id:
            scan_result = ScanResult.objects.select_related("project", "project__user").get(pk=scan_result_id)
        elif project_id:
            scan_result = ScanResult.objects.select_related("project", "project__user").filter(project_id=project_id).order_by("-started_at", "-created_at").first()
        if not scan_result:
            return Response({"detail": "A scan_result or project with at least one scan is required."}, status=status.HTTP_400_BAD_REQUEST)
        if getattr(request.user, "role", None) != "admin" and scan_result.project.user_id != request.user.id:
            return Response({"detail": "You do not have access to this report."}, status=status.HTTP_403_FORBIDDEN)
        report = PDFReportService().create_report_record(scan_result, f"scan-report-{scan_result.id}.pdf", force=True)
        return Response(ReportSerializer(report, context={"request": request}).data, status=status.HTTP_201_CREATED)
