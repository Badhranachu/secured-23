from django.db import IntegrityError
from rest_framework import serializers

from apps.common.utils import evaluate_password_strength
from apps.common.utils.targets import TargetValidationError, normalize_target_value, target_display_name
from apps.projects.models import Project
from apps.scans.models import ScanResult


class ProjectLatestScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = (
            "id",
            "status",
            "score",
            "vibe_score",
            "critical_count",
            "warning_count",
            "info_count",
            "started_at",
            "finished_at",
        )
        read_only_fields = fields


class ProjectSerializer(serializers.ModelSerializer):
    test_password = serializers.CharField(write_only=True, required=False, allow_blank=True)
    server_password = serializers.CharField(write_only=True, required=False, allow_blank=True)
    access_token = serializers.CharField(write_only=True, required=False, allow_blank=True)
    has_test_password = serializers.SerializerMethodField()
    has_server_password = serializers.SerializerMethodField()
    has_access_token = serializers.SerializerMethodField()
    latest_scan = serializers.SerializerMethodField()
    api_items_count = serializers.SerializerMethodField()
    effective_api_base_url = serializers.SerializerMethodField()
    test_password_strength = serializers.SerializerMethodField()
    server_password_strength = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = (
            "id",
            "user",
            "name",
            "domain",
            "scan_mode",
            "github_url",
            "frontend_github_url",
            "backend_github_url",
            "api_base_url",
            "effective_api_base_url",
            "test_password_strength",
            "server_password_strength",
            "api_list",
            "api_items_count",
            "stack_name",
            "subdomains",
            "test_email",
            "test_password",
            "has_test_password",
            "server_ip_address",
            "server_password",
            "has_server_password",
            "masked_token",
            "access_token",
            "has_access_token",
            "scan_enabled",
            "scan_frequency",
            "notification_email",
            "last_scanned_at",
            "next_scan_at",
            "latest_scan",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "user",
            "masked_token",
            "has_test_password",
            "has_server_password",
            "has_access_token",
            "api_items_count",
            "effective_api_base_url",
            "test_password_strength",
            "server_password_strength",
            "last_scanned_at",
            "next_scan_at",
            "latest_scan",
            "created_at",
            "updated_at",
        )
        extra_kwargs = {
            "name": {"required": False, "allow_blank": True},
        }

    def _project_queryset(self):
        request = self.context.get("request")
        queryset = Project.objects.all()
        if request and getattr(request, "user", None) and request.user.is_authenticated:
            queryset = queryset.filter(user=request.user)
        if self.instance:
            queryset = queryset.exclude(pk=self.instance.pk)
        return queryset

    def _build_unique_name(self, base_name):
        candidate = base_name
        counter = 2
        queryset = self._project_queryset()
        while queryset.filter(name=candidate).exists():
            candidate = f"{base_name} ({counter})"
            counter += 1
        return candidate

    def validate_domain(self, value):
        try:
            return normalize_target_value(value)
        except TargetValidationError as exc:
            raise serializers.ValidationError(str(exc)) from exc

    def validate_api_list(self, value):
        lines = [line.strip() for line in value.splitlines() if line.strip()]
        return "\n".join(lines)

    def validate(self, attrs):
        domain = attrs.get("domain") or getattr(self.instance, "domain", "")
        name = attrs.get("name") or getattr(self.instance, "name", "")
        scan_mode = attrs.get("scan_mode") or getattr(self.instance, "scan_mode", Project.ScanMode.ADVANCED)

        if not name and domain:
            attrs["name"] = self._build_unique_name(target_display_name(domain))
            name = attrs["name"]

        if name and self._project_queryset().filter(name=name).exists():
            raise serializers.ValidationError({
                "name": f"A project named '{name}' already exists in your workspace.",
            })

        if scan_mode == Project.ScanMode.BASIC:
            attrs["github_url"] = ""
            attrs["frontend_github_url"] = ""
            attrs["backend_github_url"] = ""
            attrs["api_base_url"] = ""
            attrs["api_list"] = ""
            attrs["stack_name"] = ""
            attrs["subdomains"] = ""
            attrs["test_email"] = ""
            attrs["server_ip_address"] = ""
        else:
            frontend_repo = (attrs.get("frontend_github_url") if "frontend_github_url" in attrs else getattr(self.instance, "frontend_github_url", "")) or ""
            backend_repo = (attrs.get("backend_github_url") if "backend_github_url" in attrs else getattr(self.instance, "backend_github_url", "")) or ""
            legacy_repo = (attrs.get("github_url") if "github_url" in attrs else getattr(self.instance, "github_url", "")) or ""
            primary_repo = frontend_repo or legacy_repo

            if not primary_repo:
                raise serializers.ValidationError({
                    "frontend_github_url": f"Add the main GitHub repository URL for {scan_mode} scan.",
                })

            attrs["frontend_github_url"] = primary_repo
            attrs["github_url"] = primary_repo
            attrs["backend_github_url"] = backend_repo

            if scan_mode == Project.ScanMode.ADVANCED:
                attrs["test_email"] = ""
                attrs["server_ip_address"] = ""
            elif scan_mode == Project.ScanMode.SERVER:
                server_ip_address = (attrs.get("server_ip_address") if "server_ip_address" in attrs else getattr(self.instance, "server_ip_address", "")) or ""
                if not server_ip_address.strip():
                    raise serializers.ValidationError({
                        "server_ip_address": "Add the server IP address or host for server scan.",
                    })
                attrs["server_ip_address"] = server_ip_address.strip()

        return attrs

    def get_has_test_password(self, obj):
        return bool(obj.encrypted_test_password)

    def get_has_server_password(self, obj):
        return bool(obj.encrypted_server_password)

    def get_has_access_token(self, obj):
        return bool(obj.encrypted_token)

    def get_api_items_count(self, obj):
        return len([line for line in (obj.api_list or "").splitlines() if line.strip()])

    def get_effective_api_base_url(self, obj):
        return obj.get_effective_api_base_url()

    def get_test_password_strength(self, obj):
        return evaluate_password_strength(obj.get_test_password(), [obj.name, obj.domain, obj.test_email, obj.notification_email])

    def get_server_password_strength(self, obj):
        return evaluate_password_strength(obj.get_server_password(), [obj.name, obj.domain, obj.server_ip_address, obj.notification_email])

    def get_latest_scan(self, obj):
        latest = obj.scan_results.order_by("-started_at", "-created_at").first()
        return ProjectLatestScanSerializer(latest).data if latest else None

    def create(self, validated_data):
        test_password = validated_data.pop("test_password", "")
        server_password = validated_data.pop("server_password", "")
        access_token = validated_data.pop("access_token", "")
        scan_mode = validated_data.get("scan_mode", Project.ScanMode.ADVANCED)

        project = Project(user=self.context["request"].user, **validated_data)
        if scan_mode == Project.ScanMode.BASIC:
            project.set_test_password("")
            project.set_server_password("")
            project.set_token("")
        elif scan_mode == Project.ScanMode.ADVANCED:
            project.set_test_password("")
            project.set_server_password("")
            if "access_token" in self.initial_data:
                project.set_token(access_token)
            else:
                project.set_token("")
        else:
            if "test_password" in self.initial_data:
                project.set_test_password(test_password)
            if "server_password" in self.initial_data:
                project.set_server_password(server_password)
            if "access_token" in self.initial_data:
                project.set_token(access_token)
        if project.scan_enabled:
            project.refresh_next_scan()
        try:
            project.save()
        except IntegrityError as exc:
            raise serializers.ValidationError({
                "name": "A project with this name already exists. Try editing the existing project instead.",
            }) from exc
        return project

    def update(self, instance, validated_data):
        test_password = validated_data.pop("test_password", None)
        server_password = validated_data.pop("server_password", None)
        access_token = validated_data.pop("access_token", None)
        scan_mode = validated_data.get("scan_mode", instance.scan_mode)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if scan_mode == Project.ScanMode.BASIC:
            instance.set_test_password("")
            instance.set_server_password("")
            instance.set_token("")
        elif scan_mode == Project.ScanMode.ADVANCED:
            instance.set_test_password("")
            instance.set_server_password("")
            if access_token is not None:
                instance.set_token(access_token)
            else:
                instance.set_token("")
        else:
            if test_password is not None:
                instance.set_test_password(test_password)
            if server_password is not None:
                instance.set_server_password(server_password)
            if access_token is not None:
                instance.set_token(access_token)

        if instance.scan_enabled:
            instance.refresh_next_scan()
        try:
            instance.save()
        except IntegrityError as exc:
            raise serializers.ValidationError({
                "name": "A project with this name already exists. Rename the project or update the existing one.",
            }) from exc
        return instance
