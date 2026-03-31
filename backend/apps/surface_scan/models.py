from django.conf import settings
from django.db import models

from apps.common.models import TimeStampedModel


class DomainScan(TimeStampedModel):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"

    class RiskLevel(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="domain_scans")
    project = models.ForeignKey("projects.Project", on_delete=models.SET_NULL, null=True, blank=True, related_name="domain_scans")
    scan_result = models.OneToOneField(
        "scans.ScanResult",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="surface_scan",
    )
    domain = models.CharField(max_length=255)
    normalized_domain = models.CharField(max_length=255, db_index=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    started_at = models.DateTimeField(blank=True, null=True)
    finished_at = models.DateTimeField(blank=True, null=True)
    http_status = models.IntegerField(blank=True, null=True)
    https_status = models.IntegerField(blank=True, null=True)
    final_url = models.URLField(max_length=500, blank=True)
    ssl_grade = models.CharField(max_length=20, blank=True)
    certificate_issuer = models.CharField(max_length=255, blank=True)
    certificate_expiry = models.DateTimeField(blank=True, null=True)
    days_to_expiry = models.IntegerField(blank=True, null=True)
    dns_json = models.JSONField(default=dict, blank=True)
    dns_status_json = models.JSONField(default=dict, blank=True)
    headers_json = models.JSONField(default=dict, blank=True)
    redirect_chain_json = models.JSONField(default=dict, blank=True)
    tls_status_json = models.JSONField(default=dict, blank=True)
    subdomains_json = models.JSONField(default=dict, blank=True)
    ct_status_json = models.JSONField(default=dict, blank=True)
    public_files_json = models.JSONField(default=dict, blank=True)
    public_file_validation_json = models.JSONField(default=dict, blank=True)
    fingerprint_json = models.JSONField(default=dict, blank=True)
    timing_json = models.JSONField(default=dict, blank=True)
    email_security_json = models.JSONField(default=dict, blank=True)
    risk_score = models.PositiveSmallIntegerField(blank=True, null=True)
    risk_level = models.CharField(max_length=20, choices=RiskLevel.choices, blank=True)
    summary = models.TextField(blank=True)
    ai_summary = models.TextField(blank=True)
    ai_provider = models.CharField(max_length=50, blank=True)
    raw_json = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ("-started_at", "-created_at")

    def __str__(self):
        return f"{self.normalized_domain} ({self.status})"


class DomainFinding(TimeStampedModel):
    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        WARNING = "warning", "Warning"
        INFO = "info", "Info"

    scan = models.ForeignKey(DomainScan, on_delete=models.CASCADE, related_name="findings")
    category = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    key = models.CharField(max_length=120)
    value = models.TextField(blank=True)
    observed_value = models.TextField(blank=True)
    expected_value = models.TextField(blank=True)
    evidence_source = models.CharField(max_length=255, blank=True)
    confidence = models.CharField(max_length=30, blank=True)
    module_name = models.CharField(max_length=120, blank=True)
    description = models.TextField()
    recommendation = models.TextField(blank=True)
    evidence = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.scan.normalized_domain}: {self.key}"
