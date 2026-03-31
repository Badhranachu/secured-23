from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.notifications.api.serializers import SendLatestSummarySerializer
from apps.notifications.models import EmailLog
from apps.notifications.services.emailer import EmailService
from apps.projects.models import Project
from apps.scans.models import ScanResult, Vulnerability


class NotificationCenterAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        projects = Project.objects.filter(user=user).order_by('name')
        email_logs = EmailLog.objects.filter(user=user).select_related('project').order_by('-created_at')[:10]
        recent_alerts = Vulnerability.objects.filter(scan_result__project__user=user).select_related('scan_result', 'scan_result__project').order_by('-created_at')[:12]
        latest_scans = ScanResult.objects.filter(project__user=user, status=ScanResult.Status.SUCCESS).select_related('project').order_by('-started_at', '-created_at')[:8]

        github_activity = []
        for scan in latest_scans:
            github = (((scan.raw_json or {}).get('detailed_report') or {}).get('github') or {})
            if not github:
                continue
            github_activity.append({
                'scan_id': scan.id,
                'project_id': scan.project_id,
                'project_name': scan.project.name,
                'provider_used': scan.provider_used or 'fallback summary',
                'repo_count': github.get('repo_count', 0),
                'scanned_file_count': github.get('scanned_file_count', 0),
                'failed_repo_count': github.get('failed_repo_count', 0),
                'discovered_route_count': github.get('discovered_route_count', 0),
                'malware_issue_count': github.get('malware_issue_count', 0),
                'overall_status': github.get('overall_status', 'not_available'),
                'started_at': scan.started_at,
            })

        return Response({
            'default_recipient': user.email,
            'provider_strategy': 'openrouter-first',
            'projects': [
                {
                    'id': project.id,
                    'name': project.name,
                    'notification_email': project.notification_email or project.user.email,
                    'scan_mode': project.scan_mode,
                    'last_scanned_at': project.last_scanned_at,
                }
                for project in projects
            ],
            'recent_emails': [
                {
                    'id': log.id,
                    'project_name': log.project.name,
                    'subject': log.subject,
                    'status': log.status,
                    'sent_at': log.sent_at,
                    'created_at': log.created_at,
                    'error_message': log.error_message,
                }
                for log in email_logs
            ],
            'recent_alerts': [
                {
                    'id': item.id,
                    'project_name': item.scan_result.project.name,
                    'severity': item.severity,
                    'title': item.title,
                    'category': item.category,
                    'location': item.file_path or item.endpoint or 'general',
                    'created_at': item.created_at,
                }
                for item in recent_alerts
            ],
            'github_activity': github_activity,
        })


class SendLatestSummaryAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = SendLatestSummarySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        project = Project.objects.filter(pk=serializer.validated_data['project_id'], user=request.user).select_related('user').first()
        if not project:
            return Response({'detail': 'Project not found.'}, status=404)

        scan_result = project.scan_results.filter(status=ScanResult.Status.SUCCESS).order_by('-started_at', '-created_at').first()
        if not scan_result:
            return Response({'detail': 'No successful scan is available for this project yet.'}, status=400)

        EmailService().send_daily_summary(
            project=project,
            scan_result=scan_result,
            attach_pdf=serializer.validated_data.get('attach_pdf', False),
        )
        return Response({'detail': f'Latest summary emailed to {project.notification_email or project.user.email}.'})
