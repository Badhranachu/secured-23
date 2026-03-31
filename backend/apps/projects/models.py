from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.common.models import TimeStampedModel
from apps.common.utils.security import decrypt_value, encrypt_value, mask_secret
from apps.common.utils.targets import default_api_base_url_for_target, target_display_name


class Project(TimeStampedModel):
    class ScanMode(models.TextChoices):
        BASIC = "basic", "Basic"
        ADVANCED = "advanced", "Advanced"
        SERVER = "server", "Server"

    class ScanFrequency(models.TextChoices):
        MANUAL = "manual", "Manual"
        DAILY = "daily", "Daily"
        WEEKLY = "weekly", "Weekly"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="projects")
    name = models.CharField(max_length=255)
    domain = models.CharField(max_length=255)
    scan_mode = models.CharField(max_length=20, choices=ScanMode.choices, default=ScanMode.ADVANCED)
    github_url = models.URLField(blank=True)
    frontend_github_url = models.URLField(blank=True)
    backend_github_url = models.URLField(blank=True)
    api_base_url = models.URLField(blank=True)
    api_list = models.TextField(blank=True, default="")
    stack_name = models.CharField(max_length=120, blank=True)
    subdomains = models.TextField(blank=True, default="")
    test_email = models.EmailField(blank=True)
    encrypted_test_password = models.TextField(blank=True)
    server_ip_address = models.CharField(max_length=255, blank=True)
    encrypted_server_password = models.TextField(blank=True)
    masked_token = models.CharField(max_length=255, blank=True)
    encrypted_token = models.TextField(blank=True)
    scan_enabled = models.BooleanField(default=False)
    scan_frequency = models.CharField(max_length=20, choices=ScanFrequency.choices, default=ScanFrequency.MANUAL)
    notification_email = models.EmailField(blank=True)
    last_scanned_at = models.DateTimeField(blank=True, null=True)
    next_scan_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("-updated_at",)
        unique_together = ("user", "name")

    def __str__(self):
        return f"{self.name} ({self.user.email})"

    def save(self, *args, **kwargs):
        self.domain = (self.domain or "").strip().lower()
        self.server_ip_address = (self.server_ip_address or "").strip()
        if not self.name and self.domain:
            self.name = self._default_name_from_domain()

        if self.notification_email:
            self.notification_email = self.notification_email.lower()
        elif self.user_id and getattr(self.user, "email", None):
            self.notification_email = self.user.email

        if self.test_email:
            self.test_email = self.test_email.lower()

        if self.scan_enabled and not self.next_scan_at:
            self.next_scan_at = self._calculate_next_scan(timezone.now())
        if not self.scan_enabled:
            self.next_scan_at = None

        super().save(*args, **kwargs)

    def _default_name_from_domain(self):
        if not self.domain:
            return "Untitled Project"
        return target_display_name(self.domain)

    def get_effective_api_base_url(self):
        if self.api_base_url:
            return self.api_base_url.rstrip("/")
        if not self.domain:
            return ""
        return default_api_base_url_for_target(self.domain).rstrip("/")

    def get_github_repositories(self):
        repositories = []
        primary_repo = self.frontend_github_url or self.github_url
        backend_repo = self.backend_github_url

        if primary_repo and backend_repo:
            repositories.append(("frontend", primary_repo))
            repositories.append(("backend", backend_repo))
            return repositories

        if primary_repo:
            repositories.append(("frontend", primary_repo))
            repositories.append(("backend", primary_repo))
            return repositories

        if backend_repo:
            repositories.append(("backend", backend_repo))
        return repositories

    def _calculate_next_scan(self, from_time):
        if self.scan_frequency == self.ScanFrequency.DAILY:
            return from_time + timedelta(days=1)
        if self.scan_frequency == self.ScanFrequency.WEEKLY:
            return from_time + timedelta(days=7)
        return None

    def refresh_next_scan(self, from_time=None):
        base_time = from_time or timezone.now()
        self.next_scan_at = self._calculate_next_scan(base_time) if self.scan_enabled else None
        return self.next_scan_at

    def set_test_password(self, raw_password: str):
        self.encrypted_test_password = encrypt_value(raw_password) if raw_password else ""

    def get_test_password(self) -> str:
        return decrypt_value(self.encrypted_test_password)

    def set_server_password(self, raw_password: str):
        self.encrypted_server_password = encrypt_value(raw_password) if raw_password else ""

    def get_server_password(self) -> str:
        return decrypt_value(self.encrypted_server_password)

    def set_token(self, raw_token: str):
        self.encrypted_token = encrypt_value(raw_token) if raw_token else ""
        self.masked_token = mask_secret(raw_token) if raw_token else ""

    def get_token(self) -> str:
        return decrypt_value(self.encrypted_token)
