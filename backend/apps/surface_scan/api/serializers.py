from rest_framework import serializers

from apps.surface_scan.models import DomainFinding, DomainScan
from apps.surface_scan.services.domain_normalizer import normalize_domain_input


class DomainFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = DomainFinding
        fields = (
            "id",
            "scan",
            "category",
            "severity",
            "key",
            "value",
            "observed_value",
            "expected_value",
            "evidence_source",
            "confidence",
            "module_name",
            "description",
            "recommendation",
            "evidence",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class DomainScanCreateSerializer(serializers.Serializer):
    domain = serializers.CharField(max_length=255)
    project_id = serializers.IntegerField(required=False)

    def validate_domain(self, value):
        return normalize_domain_input(value)


class DomainScanListSerializer(serializers.ModelSerializer):
    findings_count = serializers.SerializerMethodField()
    project_name = serializers.CharField(source="project.name", read_only=True)

    class Meta:
        model = DomainScan
        fields = (
            "id",
            "project",
            "project_name",
            "domain",
            "normalized_domain",
            "status",
            "started_at",
            "finished_at",
            "risk_score",
            "risk_level",
            "final_url",
            "http_status",
            "https_status",
            "days_to_expiry",
            "summary",
            "ai_provider",
            "findings_count",
        )
        read_only_fields = fields

    def get_findings_count(self, obj):
        return obj.findings.count()


class DomainScanDetailSerializer(DomainScanListSerializer):
    findings = DomainFindingSerializer(many=True, read_only=True)

    class Meta(DomainScanListSerializer.Meta):
        fields = DomainScanListSerializer.Meta.fields + (
            "ssl_grade",
            "certificate_issuer",
            "certificate_expiry",
            "dns_json",
            "dns_status_json",
            "headers_json",
            "redirect_chain_json",
            "tls_status_json",
            "subdomains_json",
            "ct_status_json",
            "public_files_json",
            "public_file_validation_json",
            "fingerprint_json",
            "timing_json",
            "email_security_json",
            "ai_summary",
            "raw_json",
            "error_message",
            "findings",
        )
