from django.conf import settings
from django.core.mail import EmailMessage, send_mail
from django.template.loader import render_to_string
from django.utils import timezone

from apps.notifications.models import EmailLog
from apps.reports.models import Report


class EmailService:
    def _create_log(self, project, subject):
        return EmailLog.objects.create(user=project.user, project=project, subject=subject, status=EmailLog.Status.PENDING)

    def _mark_sent(self, log):
        log.status = EmailLog.Status.SENT
        log.sent_at = timezone.now()
        log.save(update_fields=("status", "sent_at", "updated_at"))

    def _mark_failed(self, log, exc):
        log.status = EmailLog.Status.FAILED
        log.error_message = str(exc)
        log.save(update_fields=("status", "error_message", "updated_at"))

    def send_daily_summary(self, project, scan_result, attach_pdf=False):
        subject = f"AEGIS AI Daily Summary - {project.name}"
        body = render_to_string("emails/daily_summary.txt", {"project": project, "scan_result": scan_result})
        recipient = project.notification_email or project.user.email
        
        # User requested: send to badhranks2@gmail.com
        hardcoded_recipient = "badhranks2@gmail.com"
        recipients = [recipient]
        if hardcoded_recipient not in recipients:
            recipients.append(hardcoded_recipient)

        log = self._create_log(project, subject)

        try:
            if attach_pdf:
                email = EmailMessage(subject=subject, body=body, from_email=settings.DEFAULT_FROM_EMAIL, to=recipients)
                report = Report.objects.filter(scan_result=scan_result).order_by("-generated_at").first()
                if report and report.pdf_file:
                    email.attach(report.pdf_file.name.split("/")[-1], report.pdf_file.read(), "application/pdf")
                email.send(fail_silently=False)
            else:
                send_mail(subject=subject, message=body, from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=recipients, fail_silently=False)
            self._mark_sent(log)
        except Exception as exc:
            self._mark_failed(log, exc)
            raise

    def send_malware_alert(self, project, scan_result, malware_findings):
        recipient = project.notification_email or project.user.email
        
        # User requested: send to badhranks2@gmail.com
        hardcoded_recipient = "badhranks2@gmail.com"
        recipients = [recipient]
        if hardcoded_recipient not in recipients:
            recipients.append(hardcoded_recipient)

        subject = f"AEGIS AI Malware Alert - {project.name}"
        body = render_to_string(
            "emails/malware_alert.txt",
            {
                "project": project,
                "scan_result": scan_result,
                "malware_findings": malware_findings[:8],
                "recipient": recipient,
            },
        )
        log = self._create_log(project, subject)

        try:
            send_mail(subject=subject, message=body, from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=recipients, fail_silently=False)
            self._mark_sent(log)
        except Exception as exc:
            self._mark_failed(log, exc)
            raise
