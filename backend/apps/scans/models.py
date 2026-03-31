from django.conf import settings
from django.db import models

from apps.common.models import TimeStampedModel


class ScanResult(TimeStampedModel):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"

    class TriggerType(models.TextChoices):
        MANUAL = "manual", "Manual"
        SCHEDULED = "scheduled", "Scheduled"

    project = models.ForeignKey("projects.Project", on_delete=models.CASCADE, related_name="scan_results")
    initiated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_results",
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    trigger_type = models.CharField(max_length=20, choices=TriggerType.choices, default=TriggerType.MANUAL)
    started_at = models.DateTimeField(blank=True, null=True)
    finished_at = models.DateTimeField(blank=True, null=True)
    score = models.PositiveSmallIntegerField(blank=True, null=True)
    vibe_score = models.PositiveSmallIntegerField(blank=True, null=True)
    critical_count = models.PositiveIntegerField(default=0)
    warning_count = models.PositiveIntegerField(default=0)
    info_count = models.PositiveIntegerField(default=0)
    summary = models.TextField(blank=True)
    raw_json = models.JSONField(default=dict, blank=True)
    ai_summary = models.TextField(blank=True)
    provider_used = models.CharField(max_length=50, blank=True)
    failure_reason = models.TextField(blank=True)
    next_run = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("-started_at", "-created_at")

    def __str__(self):
        return f"{self.project.name} - {self.status}"


class Vulnerability(TimeStampedModel):
    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        WARNING = "warning", "Warning"
        INFO = "info", "Info"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        RESOLVED = "resolved", "Resolved"
        IGNORED = "ignored", "Ignored"

    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name="vulnerabilities")
    category = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    endpoint = models.CharField(max_length=500, blank=True)
    file_path = models.CharField(max_length=500, blank=True)
    recommendation = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    evidence = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.title} ({self.severity})"


class ScanTaskLog(TimeStampedModel):
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"

    project = models.ForeignKey("projects.Project", on_delete=models.CASCADE, related_name="task_logs")
    scan_result = models.ForeignKey(
        ScanResult,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="task_logs",
    )
    task_id = models.CharField(max_length=255, db_index=True)
    task_name = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.QUEUED)
    message = models.TextField(blank=True)
    retry_count = models.PositiveIntegerField(default=0)
    started_at = models.DateTimeField(blank=True, null=True)
    finished_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.task_name} - {self.status}"
