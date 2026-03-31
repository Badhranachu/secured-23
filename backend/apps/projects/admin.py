from django.contrib import admin

from .models import Project


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "user",
        "domain",
        "scan_mode",
        "scan_enabled",
        "scan_frequency",
        "last_scanned_at",
        "next_scan_at",
        "updated_at",
    )
    list_filter = ("scan_mode", "scan_enabled", "scan_frequency", "stack_name")
    search_fields = ("name", "domain", "user__email", "github_url", "frontend_github_url", "backend_github_url", "api_base_url", "server_ip_address")
    readonly_fields = ("masked_token", "created_at", "updated_at", "last_scanned_at", "next_scan_at")
