from django.contrib import admin

from .models import Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("id", "project", "scan_result", "generated_at")
    search_fields = ("project__name", "project__user__email")
    readonly_fields = ("generated_at", "created_at", "updated_at")
