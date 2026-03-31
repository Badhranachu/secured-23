from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

admin.site.site_header = "AEGIS AI Admin"
admin.site.site_title = "AEGIS AI"
admin.site.index_title = "Security Scanner Control Panel"

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/health/", include("apps.common.api.urls")),
    path("api/v1/auth/", include("apps.accounts.api.urls")),
    path("api/v1/projects/", include("apps.projects.api.urls")),
    path("api/v1/scans/", include("apps.scans.api.urls")),
    path("api/v1/reports/", include("apps.reports.api.urls")),
    path("api/v1/dashboard/", include("apps.analytics.api.urls")),
    path("api/v1/domain-scans/", include("apps.surface_scan.api.urls")),
    path("api/v1/notifications/", include("apps.notifications.api.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
