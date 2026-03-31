from django.urls import path

from .views import AdminDashboardSummaryAPIView, UserDashboardSummaryAPIView

urlpatterns = [
    path("user-summary/", UserDashboardSummaryAPIView.as_view(), name="dashboard-user-summary"),
    path("admin-summary/", AdminDashboardSummaryAPIView.as_view(), name="dashboard-admin-summary"),
]
