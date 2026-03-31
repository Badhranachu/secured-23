from rest_framework import serializers

from apps.scans.models import ScanResult, Vulnerability


class VulnerabilitySerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="scan_result.project.name", read_only=True)

    class Meta:
        model = Vulnerability
        fields = (
            "id",
            "scan_result",
            "project_name",
            "category",
            "severity",
            "title",
            "description",
            "endpoint",
            "file_path",
            "recommendation",
            "status",
            "evidence",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class ScanResultListSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="project.name", read_only=True)
    user_email = serializers.CharField(source="project.user.email", read_only=True)

    class Meta:
        model = ScanResult
        fields = (
            "id",
            "project",
            "project_name",
            "user_email",
            "status",
            "trigger_type",
            "started_at",
            "finished_at",
            "score",
            "vibe_score",
            "critical_count",
            "warning_count",
            "info_count",
            "summary",
            "provider_used",
            "next_run",
        )
        read_only_fields = fields


class ScanResultDetailSerializer(ScanResultListSerializer):
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)

    class Meta(ScanResultListSerializer.Meta):
        fields = ScanResultListSerializer.Meta.fields + (
            "raw_json",
            "ai_summary",
            "failure_reason",
            "vulnerabilities",
        )
