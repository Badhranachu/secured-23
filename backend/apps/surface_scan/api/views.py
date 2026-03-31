from django.db.models import Avg, Count, Q
from django.db.models.functions import TruncDate
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.common.utils.targets import target_display_name
from apps.projects.models import Project
from apps.surface_scan.api.serializers import (
    DomainFindingSerializer,
    DomainScanCreateSerializer,
    DomainScanDetailSerializer,
    DomainScanListSerializer,
)
from apps.surface_scan.models import DomainScan
from apps.surface_scan.tasks import run_domain_scan


class DomainScanViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    ordering = ("-started_at",)
    search_fields = ("domain", "normalized_domain", "summary", "ai_summary")
    ordering_fields = ("started_at", "finished_at", "risk_score", "days_to_expiry")

    def get_queryset(self):
        queryset = DomainScan.objects.select_related("user", "project", "scan_result").prefetch_related("findings")
        if getattr(self.request.user, "role", None) != "admin":
            queryset = queryset.filter(user=self.request.user)
        risk_level = self.request.query_params.get("risk_level")
        status_value = self.request.query_params.get("status")
        if risk_level:
            queryset = queryset.filter(risk_level=risk_level)
        if status_value:
            queryset = queryset.filter(status=status_value)
        return queryset

    def get_serializer_class(self):
        return DomainScanDetailSerializer if self.action in {"retrieve", "findings"} else DomainScanListSerializer

    @action(detail=False, methods=["post"], url_path="scan")
    def scan(self, request):
        serializer = DomainScanCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        project = None
        project_id = serializer.validated_data.get("project_id")
        if project_id:
            project_queryset = Project.objects.filter(pk=project_id)
            if getattr(request.user, "role", None) != "admin":
                project_queryset = project_queryset.filter(user=request.user)
            project = project_queryset.first()

        domain_scan = DomainScan.objects.create(
            user=request.user,
            project=project,
            domain=serializer.validated_data["domain"],
            normalized_domain=serializer.validated_data["domain"],
            status=DomainScan.Status.PENDING,
        )

        try:
            task = run_domain_scan.delay(domain_scan.id)
            return Response({"id": domain_scan.id, "task_id": task.id, "status": domain_scan.status}, status=status.HTTP_202_ACCEPTED)
        except Exception:
            run_domain_scan(domain_scan.id)
            domain_scan.refresh_from_db()
            return Response(DomainScanDetailSerializer(domain_scan, context={"request": request}).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["get"], url_path="findings")
    def findings(self, request, pk=None):
        scan = self.get_object()
        return Response(DomainFindingSerializer(scan.findings.all(), many=True, context={"request": request}).data)

    @action(detail=False, methods=["get"], url_path="dashboard-summary")
    def dashboard_summary(self, request):
        queryset = self.get_queryset().filter(status=DomainScan.Status.SUCCESS)
        totals = queryset.aggregate(
            total_scans=Count("id"),
            average_risk_score=Avg("risk_score"),
            high_risk_domains=Count("id", filter=Q(risk_level__in=[DomainScan.RiskLevel.HIGH, DomainScan.RiskLevel.CRITICAL])),
            expiring_certificates=Count("id", filter=Q(days_to_expiry__isnull=False, days_to_expiry__lte=15)),
        )
        scan_count_by_day = list(
            queryset.annotate(date=TruncDate("started_at")).values("date").annotate(total=Count("id")).order_by("date")
        )
        risk_score_over_time = list(
            queryset.annotate(date=TruncDate("started_at")).values("date").annotate(score=Avg("risk_score")).order_by("date")
        )
        missing_headers_over_time = []
        for scan in queryset.order_by("started_at")[:50]:
            summary = scan.headers_json.get("summary", {}) if isinstance(scan.headers_json, dict) else {}
            missing_headers_over_time.append({"date": scan.started_at.date().isoformat() if scan.started_at else "", "missing_headers": summary.get("missing_count", 0)})

        latest_by_domain = {}
        for scan in queryset.order_by("normalized_domain", "-started_at", "-created_at"):
            canonical_domain = target_display_name(scan.normalized_domain or scan.domain)
            latest_by_domain.setdefault(canonical_domain, scan)

        latest_domain_rows = sorted(
            [
                {
                    "domain": target_display_name(scan.normalized_domain or scan.domain),
                    "raw_domain": scan.normalized_domain,
                    "days_to_expiry": scan.days_to_expiry,
                    "risk_score": scan.risk_score,
                    "risk_level": scan.risk_level,
                    "last_scanned_at": scan.started_at.isoformat() if scan.started_at else None,
                    "status": scan.status,
                    "final_url": scan.final_url,
                }
                for scan in latest_by_domain.values()
                if scan.days_to_expiry is not None
            ],
            key=lambda item: item["days_to_expiry"],
        )[:20]

        return Response(
            {
                "total_scans": totals.get("total_scans", 0),
                "average_risk_score": round(totals.get("average_risk_score") or 0, 1),
                "high_risk_domains_count": totals.get("high_risk_domains", 0),
                "expiring_certificates_count": totals.get("expiring_certificates", 0),
                "risk_score_over_time": risk_score_over_time,
                "missing_headers_over_time": missing_headers_over_time,
                "certificate_expiry_trend": latest_domain_rows,
                "scan_count_by_day": scan_count_by_day,
                "unique_domains_tracked": len(latest_by_domain),
            }
        )
