from django.db import models

from apps.common.models import TimeStampedModel


class Report(TimeStampedModel):
    project = models.ForeignKey("projects.Project", on_delete=models.CASCADE, related_name="reports")
    scan_result = models.ForeignKey("scans.ScanResult", on_delete=models.CASCADE, related_name="reports")
    pdf_file = models.FileField(upload_to="reports/%Y/%m/%d/", blank=True, null=True)
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-generated_at",)

    def __str__(self):
        return f"Report {self.id} - {self.project.name}"
