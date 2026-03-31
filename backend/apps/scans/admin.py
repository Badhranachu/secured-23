from django.contrib import admin

from .models import ScanResult, ScanTaskLog, Vulnerability


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = (
        "project",
        "status",
        "trigger_type",
        "score",
        "vibe_score",
        "critical_count",
        "warning_count",
        "started_at",
        "finished_at",
    )
    list_filter = ("status", "trigger_type", "provider_used")
    search_fields = ("project__name", "project__user__email", "summary", "ai_summary")
    readonly_fields = ("raw_json", "created_at", "updated_at")


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("title", "scan_result", "category", "severity", "status", "endpoint", "created_at")
    list_filter = ("severity", "status", "category")
    search_fields = ("title", "description", "endpoint", "file_path")


@admin.register(ScanTaskLog)
class ScanTaskLogAdmin(admin.ModelAdmin):
    list_display = ("task_name", "project", "status", "retry_count", "started_at", "finished_at")
    list_filter = ("status",)
    search_fields = ("task_name", "task_id", "project__name", "message")
