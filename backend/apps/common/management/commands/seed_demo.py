from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.accounts.models import User
from apps.projects.models import Project
from apps.scans.models import ScanResult, Vulnerability


class Command(BaseCommand):
    help = 'Seed local demo data for AEGIS AI.'

    def handle(self, *args, **options):
        admin, _ = User.objects.get_or_create(
            email='admin@aegis.local',
            defaults={'name': 'AEGIS Admin', 'role': User.Role.ADMIN, 'is_staff': True, 'is_superuser': True},
        )
        admin.set_password('Admin123!')
        admin.save()

        user, _ = User.objects.get_or_create(
            email='demo@aegis.local',
            defaults={'name': 'Demo User', 'role': User.Role.USER},
        )
        user.set_password('Demo123!')
        user.save()

        project, _ = Project.objects.get_or_create(
            user=user,
            name='Demo Commerce API',
            defaults={
                'domain': 'example.com',
                'github_url': 'https://github.com/octocat/Hello-World',
                'frontend_github_url': 'https://github.com/octocat/Hello-World',
                'backend_github_url': 'https://github.com/octocat/Spoon-Knife',
                'api_base_url': 'https://example.com',
                'api_list': 'GET /api/profile\nGET /api/admin/users\nPOST /api/login',
                'stack_name': 'Django + React',
                'scan_enabled': True,
                'scan_frequency': Project.ScanFrequency.DAILY,
                'notification_email': 'demo@aegis.local',
            },
        )
        project.refresh_next_scan(timezone.now())
        project.save()

        scan = ScanResult.objects.create(
            project=project,
            initiated_by=user,
            status=ScanResult.Status.SUCCESS,
            trigger_type=ScanResult.TriggerType.MANUAL,
            started_at=timezone.now(),
            finished_at=timezone.now(),
            score=71,
            vibe_score=34,
            critical_count=1,
            warning_count=2,
            info_count=1,
            summary='Demo data seeded successfully.',
            ai_summary='A sample project was seeded with a critical admin exposure and supporting warnings.',
            raw_json={'seeded': True},
        )

        Vulnerability.objects.get_or_create(
            scan_result=scan,
            title='Admin-like endpoint exposed without auth',
            defaults={
                'category': 'api_endpoints',
                'severity': 'critical',
                'description': 'Seed data for UI demos.',
                'endpoint': '/api/admin/users',
                'recommendation': 'Protect the endpoint with RBAC.',
            },
        )

        self.stdout.write(self.style.SUCCESS('Demo seed complete.'))
