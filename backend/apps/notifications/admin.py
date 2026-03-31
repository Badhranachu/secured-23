from django.contrib import admin

from .models import EmailLog


@admin.register(EmailLog)
class EmailLogAdmin(admin.ModelAdmin):
    list_display = ("subject", "user", "project", "status", "sent_at", "created_at")
    list_filter = ("status",)
    search_fields = ("subject", "user__email", "project__name", "error_message")
