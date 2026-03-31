from collections import defaultdict
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db.models import Avg, Count, Max
from django.utils import timezone

from apps.projects.models import Project
from apps.scans.models import ScanResult, Vulnerability

User = get_user_model()


class DashboardService:
    def get_user_summary(self, user):
        projects = Project.objects.filter(user=user)
        scans = ScanResult.objects.filter(project__user=user).select_related("project")
        latest_scan = scans.order_by("-started_at", "-created_at").first()

        score_over_time = [
            {"date": item.started_at.date().isoformat(), "score": item.score or 0}
            for item in scans.exclude(score__isnull=True).order_by("started_at")[:30]
        ]
        vibe_over_time = [
            {"date": item.started_at.date().isoformat(), "vibe_score": item.vibe_score or 0}
            for item in scans.exclude(vibe_score__isnull=True).order_by("started_at")[:30]
        ]
        critical_over_time = [
            {"date": item.started_at.date().isoformat(), "critical_count": item.critical_count}
            for item in scans.order_by("started_at")[:30]
        ]
        issue_category_breakdown = list(
            Vulnerability.objects.filter(scan_result__project__user=user)
            .values("category")
            .annotate(total=Count("id"))
            .order_by("-total")[:8]
        )
        scan_history = [
            {
                "id": item.id,
                "project": item.project.name,
                "status": item.status,
                "score": item.score,
                "vibe_score": item.vibe_score,
                "critical_count": item.critical_count,
                "started_at": item.started_at,
            }
            for item in scans.order_by("-started_at", "-created_at")[:10]
        ]

        return {
            "total_projects": projects.count(),
            "last_scan_time": latest_scan.started_at if latest_scan else None,
            "current_security_score": latest_scan.score if latest_scan else None,
            "vibe_risk_score": latest_scan.vibe_score if latest_scan else None,
            "critical_findings": latest_scan.critical_count if latest_scan else 0,
            "warning_findings": latest_scan.warning_count if latest_scan else 0,
            "next_scheduled_scan": projects.filter(scan_enabled=True).order_by("next_scan_at").values_list("next_scan_at", flat=True).first(),
            "score_over_time": score_over_time,
            "vibe_over_time": vibe_over_time,
            "critical_over_time": critical_over_time,
            "issue_category_breakdown": issue_category_breakdown,
            "scan_history": scan_history,
        }

    def get_admin_summary(self):
        projects = Project.objects.select_related("user")
        scans = ScanResult.objects.select_related("project", "project__user")
        today = timezone.now().date()
        daily_points = []
        for offset in range(13, -1, -1):
            day = today - timedelta(days=offset)
            day_scans = scans.filter(started_at__date=day)
            daily_points.append({
                "date": day.isoformat(),
                "total": day_scans.count(),
                "success": day_scans.filter(status=ScanResult.Status.SUCCESS).count(),
                "failed": day_scans.filter(status=ScanResult.Status.FAILED).count(),
            })

        active_user_points = []
        for offset in range(13, -1, -1):
            day = today - timedelta(days=offset)
            active_user_points.append({
                "date": day.isoformat(),
                "active_users": User.objects.filter(last_login__date__lte=day).exclude(last_login__isnull=True).count(),
            })

        highest_risk_projects = list(
            scans.values("project_id", "project__name", "project__user__email")
            .annotate(risk=Avg("score"), last_scan=Max("started_at"))
            .order_by("risk")[:10]
        )

        most_common_issue_types = list(
            Vulnerability.objects.values("category")
            .annotate(total=Count("id"))
            .order_by("-total")[:10]
        )

        user_project_rows = [
            {
                "user_id": project.user_id,
                "user_email": project.user.email,
                "project_id": project.id,
                "project_name": project.name,
                "scan_enabled": project.scan_enabled,
                "next_scan_at": project.next_scan_at,
            }
            for project in projects.order_by("user__email", "name")[:50]
        ]

        return {
            "total_users": User.objects.count(),
            "total_projects": projects.count(),
            "total_scans": scans.count(),
            "active_projects": projects.filter(scan_enabled=True).count(),
            "failed_scans": scans.filter(status=ScanResult.Status.FAILED).count(),
            "highest_risk_projects": highest_risk_projects,
            "most_common_issue_types": most_common_issue_types,
            "daily_scan_volume": daily_points,
            "failed_vs_successful": daily_points,
            "active_users_over_time": active_user_points,
            "user_project_rows": user_project_rows,
        }
