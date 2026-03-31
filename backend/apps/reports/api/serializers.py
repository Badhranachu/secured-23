from rest_framework import serializers

from apps.reports.models import Report


class ReportSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="project.name", read_only=True)

    class Meta:
        model = Report
        fields = ("id", "project", "project_name", "scan_result", "pdf_file", "generated_at")
        read_only_fields = fields
