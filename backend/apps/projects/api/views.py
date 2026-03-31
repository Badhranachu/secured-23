from celery.exceptions import CeleryError
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.common.permissions import IsOwnerOrAdmin
from apps.projects.models import Project
from apps.scans.api.serializers import ScanResultDetailSerializer, ScanResultListSerializer
from apps.scans.services.pipeline import ScanPipeline
from apps.scans.tasks import run_project_scan

from .serializers import ProjectSerializer


class ProjectViewSet(viewsets.ModelViewSet):
    serializer_class = ProjectSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]
    search_fields = ("name", "domain", "github_url", "frontend_github_url", "backend_github_url", "api_base_url", "stack_name")
    ordering_fields = ("created_at", "updated_at", "last_scanned_at", "next_scan_at", "name")
    ordering = ("-updated_at",)

    def get_queryset(self):
        queryset = Project.objects.select_related("user").prefetch_related("scan_results")
        if getattr(self.request.user, "role", None) != "admin":
            queryset = queryset.filter(user=self.request.user)

        scan_enabled = self.request.query_params.get("scan_enabled")
        scan_frequency = self.request.query_params.get("scan_frequency")
        user_id = self.request.query_params.get("user")

        if scan_enabled in {"true", "false"}:
            queryset = queryset.filter(scan_enabled=scan_enabled == "true")
        if scan_frequency:
            queryset = queryset.filter(scan_frequency=scan_frequency)
        if user_id and getattr(self.request.user, "role", None) == "admin":
            queryset = queryset.filter(user_id=user_id)
        return queryset

    def perform_create(self, serializer):
        serializer.save()

    @action(detail=True, methods=["post"], url_path="scan-now")
    def scan_now(self, request, pk=None):
        project = self.get_object()
        run_sync = request.data.get("sync") in {True, "true", "1", 1}

        if run_sync:
            result = ScanPipeline().run(project=project, initiated_by=request.user)
            return Response(
                {
                    "detail": "Scan completed synchronously.",
                    "scan_result": ScanResultDetailSerializer(result, context={"request": request}).data,
                },
                status=status.HTTP_200_OK,
            )

        try:
            task = run_project_scan.delay(project_id=project.id, trigger_type="manual", initiated_by_id=request.user.id)
            return Response(
                {"detail": "Scan queued.", "task_id": task.id, "project_id": project.id},
                status=status.HTTP_202_ACCEPTED,
            )
        except Exception:
            result = ScanPipeline().run(project=project, initiated_by=request.user)
            return Response(
                {
                    "detail": "Celery unavailable, scan executed synchronously.",
                    "scan_result": ScanResultDetailSerializer(result, context={"request": request}).data,
                },
                status=status.HTTP_200_OK,
            )

    @action(detail=True, methods=["post"], url_path="toggle-schedule")
    def toggle_schedule(self, request, pk=None):
        project = self.get_object()
        enabled = request.data.get("scan_enabled")
        if enabled is not None:
            project.scan_enabled = str(enabled).lower() in {"true", "1", "yes"}
        frequency = request.data.get("scan_frequency")
        if frequency in {choice[0] for choice in Project.ScanFrequency.choices}:
            project.scan_frequency = frequency
        project.refresh_next_scan()
        project.save()
        return Response(ProjectSerializer(project, context={"request": request}).data)

    @action(detail=True, methods=["get"], url_path="latest-scan")
    def latest_scan(self, request, pk=None):
        project = self.get_object()
        latest = project.scan_results.order_by("-started_at", "-created_at").first()
        if not latest:
            return Response({"detail": "No scans found for this project."}, status=status.HTTP_404_NOT_FOUND)
        return Response(ScanResultDetailSerializer(latest, context={"request": request}).data)

    @action(detail=True, methods=["get"], url_path="scan-history")
    def scan_history(self, request, pk=None):
        project = self.get_object()
        scans = project.scan_results.order_by("-started_at", "-created_at")[:25]
        return Response(ScanResultListSerializer(scans, many=True, context={"request": request}).data)
