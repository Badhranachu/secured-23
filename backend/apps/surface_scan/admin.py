from django.contrib import admin

from apps.surface_scan.models import DomainFinding, DomainScan


class DomainFindingInline(admin.TabularInline):
    model = DomainFinding
    extra = 0
    readonly_fields = ("category", "severity", "key", "value", "description", "recommendation", "evidence", "created_at")
    can_delete = False


@admin.register(DomainScan)
class DomainScanAdmin(admin.ModelAdmin):
    list_display = ("id", "normalized_domain", "status", "risk_score", "risk_level", "user", "started_at", "finished_at")
    list_filter = ("status", "risk_level", "started_at")
    search_fields = ("domain", "normalized_domain", "user__email")
    readonly_fields = (
        "started_at",
        "finished_at",
        "http_status",
        "https_status",
        "final_url",
        "ssl_grade",
        "certificate_issuer",
        "certificate_expiry",
        "days_to_expiry",
        "dns_json",
        "headers_json",
        "subdomains_json",
        "public_files_json",
        "risk_score",
        "risk_level",
        "summary",
        "ai_summary",
        "ai_provider",
        "raw_json",
        "error_message",
        "created_at",
        "updated_at",
    )
    inlines = [DomainFindingInline]


@admin.register(DomainFinding)
class DomainFindingAdmin(admin.ModelAdmin):
    list_display = ("scan", "category", "severity", "key", "created_at")
    list_filter = ("category", "severity", "created_at")
    search_fields = ("scan__normalized_domain", "description", "recommendation", "key", "value")
