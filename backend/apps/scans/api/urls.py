from rest_framework.routers import DefaultRouter

from .views import ScanResultViewSet, VulnerabilityViewSet

router = DefaultRouter()
router.register("results", ScanResultViewSet, basename="scan-result")
router.register("vulnerabilities", VulnerabilityViewSet, basename="vulnerability")

urlpatterns = router.urls
