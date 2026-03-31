import logging

from celery import shared_task
from django.contrib.auth import get_user_model
from django.utils import timezone

from apps.notifications.tasks import send_scan_summary_email
from apps.projects.models import Project
from apps.reports.services.pdf import PDFReportService
from apps.scans.models import ScanResult, ScanTaskLog
from apps.scans.services.pipeline import ScanPipeline

User = get_user_model()
logger = logging.getLogger(__name__)


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def run_project_scan(self, project_id, trigger_type="manual", initiated_by_id=None, send_email=False, attach_pdf=False):
    project = Project.objects.select_related("user").get(pk=project_id)
    initiated_by = User.objects.filter(pk=initiated_by_id).first() if initiated_by_id else None
    task_log = ScanTaskLog.objects.create(
        project=project,
        task_id=self.request.id,
        task_name="run_project_scan",
        status=ScanTaskLog.Status.RUNNING,
        started_at=timezone.now(),
        retry_count=self.request.retries,
    )

    try:
        logger.info("[TASK %s] starting project scan for project=%s trigger=%s retry=%s", self.request.id, project.id, trigger_type, self.request.retries)
        scan_result = ScanPipeline().run(project=project, initiated_by=initiated_by, trigger_type=trigger_type)
        task_log.scan_result = scan_result
        task_log.status = ScanTaskLog.Status.SUCCESS if scan_result.status == ScanResult.Status.SUCCESS else ScanTaskLog.Status.FAILED
        task_log.finished_at = timezone.now()
        task_log.message = scan_result.summary
        task_log.save(update_fields=("scan_result", "status", "finished_at", "message", "updated_at"))

        logger.info("[TASK %s] finished project scan for project=%s status=%s", self.request.id, project.id, scan_result.status)
        if scan_result.status == ScanResult.Status.SUCCESS:
            try:
                PDFReportService().create_report_record(scan_result, f"scan-report-{scan_result.id}.pdf")
            except Exception:
                pass
        return scan_result.id
    except Exception as exc:
        logger.exception("[TASK %s] project scan failed for project=%s", self.request.id, project.id)
        task_log.status = ScanTaskLog.Status.FAILED
        task_log.finished_at = timezone.now()
        task_log.message = str(exc)
        task_log.save(update_fields=("status", "finished_at", "message", "updated_at"))
        raise


@shared_task
def dispatch_due_project_scans():
    now = timezone.now()
    project_ids = Project.objects.filter(scan_enabled=True, next_scan_at__isnull=False, next_scan_at__lte=now).values_list("id", flat=True)
    for project_id in project_ids:
        run_project_scan.delay(project_id=project_id, trigger_type="scheduled", send_email=True, attach_pdf=False)


@shared_task
def enqueue_daily_scans():
    project_ids = Project.objects.filter(scan_enabled=True, scan_frequency=Project.ScanFrequency.DAILY).values_list("id", flat=True)
    for project_id in project_ids:
        run_project_scan.delay(project_id=project_id, trigger_type="scheduled", send_email=True)
