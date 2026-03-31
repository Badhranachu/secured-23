from rest_framework.routers import DefaultRouter

from apps.surface_scan.api.views import DomainScanViewSet

router = DefaultRouter()
router.register("", DomainScanViewSet, basename="domain-scan")

urlpatterns = router.urls
