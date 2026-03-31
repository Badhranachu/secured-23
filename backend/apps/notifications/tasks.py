from celery import shared_task

from apps.notifications.services.emailer import EmailService
from apps.projects.models import Project
from apps.scans.models import ScanResult


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def send_scan_summary_email(self, project_id, scan_result_id, attach_pdf=False):
    project = Project.objects.select_related("user").get(pk=project_id)
    scan_result = ScanResult.objects.get(pk=scan_result_id, project=project)
    EmailService().send_daily_summary(project=project, scan_result=scan_result, attach_pdf=attach_pdf)
