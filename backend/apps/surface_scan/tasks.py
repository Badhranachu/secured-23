from celery import shared_task

from apps.surface_scan.services.orchestrator import SurfaceScanOrchestrator


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 2})
def run_domain_scan(self, scan_id):
    return SurfaceScanOrchestrator().run(scan_id)
