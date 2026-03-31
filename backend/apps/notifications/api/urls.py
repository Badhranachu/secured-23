from django.urls import path

from .views import NotificationCenterAPIView, SendLatestSummaryAPIView

urlpatterns = [
    path('center/', NotificationCenterAPIView.as_view(), name='notifications-center'),
    path('send-latest-summary/', SendLatestSummaryAPIView.as_view(), name='notifications-send-latest-summary'),
]
